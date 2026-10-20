//! Fresh, bounded read-only remote logical-session authority.
//! Orchestration owns the session record; this provider has no local fallback.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use forge_control::{
    AgentSessionAuthority, AgentSessionAuthorityFailure, AgentSessionResolveRequest, ControlError,
};
use forge_domain::{OpenAgentSession, RegisteredAgentSession};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderValue,
};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::from_slice;
use tokio::runtime::Handle;

use crate::session_protocol::{RemoteSessionResolveReply, RemoteSessionResolveRequest};

const MAX_REMOTE_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_HEADER_FIELDS: usize = 16;
const RESOLVE_PATH: &str = "/internal/v1/sessions/resolve";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteAuthorityConfigError {
    NonLoopbackAuthority,
    MissingAuthorityPort,
    EmptyServiceBearer,
    InvalidServiceBearer,
}

impl fmt::Display for RemoteAuthorityConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackAuthority => formatter.write_str("remote authority must be loopback"),
            Self::MissingAuthorityPort => {
                formatter.write_str("remote authority port must be nonzero")
            }
            Self::EmptyServiceBearer => formatter.write_str("remote service bearer is empty"),
            Self::InvalidServiceBearer => formatter.write_str("remote service bearer is invalid"),
        }
    }
}

impl std::error::Error for RemoteAuthorityConfigError {}

/// One-shot remote authority client for the synchronous control-worker port.
///
/// The client uses one HTTP/1 connection per resolve and never owns a
/// background task, pool, retry loop, redirect policy, or local catalog.
pub struct RemoteAgentSessionAuthority {
    runtime: Handle,
    authority: SocketAddr,
    service_bearer: HeaderValue,
    timeout: Duration,
}

impl fmt::Debug for RemoteAgentSessionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAgentSessionAuthority")
            .field("authority", &self.authority)
            .field("timeout", &self.timeout)
            .field("service_bearer_configured", &true)
            .finish_non_exhaustive()
    }
}

impl RemoteAgentSessionAuthority {
    pub fn new(
        runtime: Handle,
        authority: SocketAddr,
        service_secret: &str,
        timeout: Duration,
    ) -> Result<Self, RemoteAuthorityConfigError> {
        if !authority.ip().is_loopback() {
            return Err(RemoteAuthorityConfigError::NonLoopbackAuthority);
        }
        if authority.port() == 0 {
            return Err(RemoteAuthorityConfigError::MissingAuthorityPort);
        }
        if service_secret.is_empty() {
            return Err(RemoteAuthorityConfigError::EmptyServiceBearer);
        }
        let mut service_bearer = HeaderValue::from_str(&format!("Bearer {service_secret}"))
            .map_err(|_| RemoteAuthorityConfigError::InvalidServiceBearer)?;
        service_bearer.set_sensitive(true);
        Ok(Self {
            runtime,
            authority,
            service_bearer,
            timeout: timeout.min(MAX_REMOTE_AUTHORITY_TIMEOUT),
        })
    }

    async fn resolve_remote(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<Option<RegisteredAgentSession>, ()> {
        let wire_request = RemoteSessionResolveRequest::from_request(&request).map_err(|_| ())?;
        let payload = serde_json::to_vec(&wire_request).map_err(|_| ())?;
        let stream = tokio::net::TcpStream::connect(self.authority)
            .await
            .map_err(|_| ())?;

        let mut builder = hyper::client::conn::http1::Builder::new();
        builder
            .max_headers(MAX_HEADER_FIELDS)
            .max_buf_size(MAX_HEADER_BYTES);
        let (mut sender, connection) = builder
            .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|_| ())?;

        let request = Request::builder()
            .method(Method::POST)
            .uri(RESOLVE_PATH)
            .header(HOST, self.authority.to_string())
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, payload.len().to_string())
            .header(CONNECTION, "close")
            .header(AUTHORIZATION, self.service_bearer.clone())
            .body(Full::new(Bytes::from(payload)))
            .map_err(|_| ())?;

        if request.headers().len() > MAX_HEADER_FIELDS
            || header_bytes(request.headers()) > MAX_HEADER_BYTES
        {
            return Err(());
        }

        let exchange = async move {
            let response = sender.send_request(request).await.map_err(|_| ())?;
            if response.status() != StatusCode::OK
                || response.headers().len() > MAX_HEADER_FIELDS
                || header_bytes(response.headers()) > MAX_HEADER_BYTES
            {
                return Err(());
            }
            let collected = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|_| ())?;
            let reply: RemoteSessionResolveReply =
                from_slice(&collected.to_bytes()).map_err(|_| ())?;
            reply.into_session().map_err(|_| ())
        };
        let mut connection = Box::pin(connection);
        let mut exchange = Box::pin(exchange);
        tokio::select! {
            result = &mut exchange => result,
            _connection_result = &mut connection => exchange.await,
        }
    }

    fn resolve_uncached(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<Option<RegisteredAgentSession>, AgentSessionAuthorityFailure> {
        let result = self.runtime.block_on(async {
            tokio::time::timeout(self.timeout, self.resolve_remote(request)).await
        });
        match result {
            Ok(Ok(session)) => Ok(session),
            Ok(Err(())) | Err(_) => Err(AgentSessionAuthorityFailure::Unavailable),
        }
    }
}

impl AgentSessionAuthority for RemoteAgentSessionAuthority {
    fn open(
        &self,
        _request: &OpenAgentSession,
    ) -> Result<forge_domain::AgentSessionOpenOutcome, ControlError> {
        Err(AgentSessionAuthorityFailure::Conflict.into_control_error())
    }

    fn resolve(
        &self,
        request: AgentSessionResolveRequest,
    ) -> Result<Option<RegisteredAgentSession>, ControlError> {
        let Some(session) = self
            .resolve_uncached(request)
            .map_err(AgentSessionAuthorityFailure::into_control_error)?
        else {
            return Ok(None);
        };
        if session.id() != request.session_id || session.principal() != request.principal {
            return Err(AgentSessionAuthorityFailure::Conflict.into_control_error());
        }
        Ok(Some(session))
    }
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    })
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use forge_control::ControlErrorCode;
    use forge_domain::{
        AgentSessionId, AgentSessionOpenRequestId, AuthenticatedPrincipal, OAuthGrantId,
        TimestampMillis,
    };
    use uuid::Uuid;

    use super::*;

    fn request(
        session_id: AgentSessionId,
        principal: AuthenticatedPrincipal,
    ) -> AgentSessionResolveRequest {
        AgentSessionResolveRequest {
            session_id,
            principal,
        }
    }

    const SERVER_DEADLINE: Duration = Duration::from_secs(5);

    struct TestServer {
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<std::io::Result<()>>>,
    }

    impl TestServer {
        fn join(mut self) -> Result<(), Box<dyn std::error::Error>> {
            let handle = self
                .handle
                .take()
                .ok_or_else(|| io::Error::other("test authority thread was already joined"))?;
            let result = handle
                .join()
                .map_err(|_| io::Error::other("test authority thread panicked"))?;
            result?;
            Ok(())
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn spawn_replies(
        listener: TcpListener,
        replies: Vec<(u16, Vec<u8>)>,
    ) -> Result<TestServer, std::io::Error> {
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let handle = std::thread::spawn(move || {
            for (status, body) in replies {
                let deadline = Instant::now() + SERVER_DEADLINE;
                let (mut stream, _) = loop {
                    if thread_stop.load(Ordering::Acquire) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "test authority stopped before serving replies",
                        ));
                    }
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "test authority reply deadline elapsed",
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_nonblocking(true)?;
                read_complete_request(&mut stream, deadline)?;
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.set_nonblocking(false)?;
                stream.set_write_timeout(Some(remaining_server_time(deadline)?))?;
                stream.write_all(head.as_bytes())?;
                stream.write_all(&body)?;
            }
            Ok(())
        });
        Ok(TestServer {
            stop,
            handle: Some(handle),
        })
    }

    fn read_complete_request(
        stream: &mut std::net::TcpStream,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut bytes = [0_u8; 4096];
        let mut received = 0;
        let mut expected = None;
        loop {
            let limit = expected.unwrap_or(bytes.len());
            if received == limit {
                return if expected.is_some() {
                    Ok(())
                } else {
                    Err(io::Error::other("test request headers exceed bound"))
                };
            }
            // Deliberately exercise partial reads while preserving the same
            // per-resolve deadline as the production remote authority.
            let read_end = limit.min(received + 64);
            let count = match stream.read(&mut bytes[received..read_end]) {
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    remaining_server_time(deadline)?;
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(error),
            };
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            received += count;
            if expected.is_none()
                && let Some(end) = bytes[..received]
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
            {
                let head = std::str::from_utf8(&bytes[..end]).map_err(io::Error::other)?;
                let length = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .ok_or_else(|| io::Error::other("test request content length missing"))?
                    .1
                    .trim()
                    .parse::<usize>()
                    .map_err(io::Error::other)?;
                let total = (end + 4)
                    .checked_add(length)
                    .filter(|total| *total <= bytes.len())
                    .ok_or_else(|| io::Error::other("test request body exceeds bound"))?;
                if received >= total {
                    return Ok(());
                }
                expected = Some(total);
            }
        }
    }

    fn remaining_server_time(deadline: Instant) -> io::Result<Duration> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test authority reply deadline elapsed",
            ));
        }
        Ok(remaining)
    }

    fn spawn_reply(
        listener: TcpListener,
        status: u16,
        body: Vec<u8>,
    ) -> Result<TestServer, std::io::Error> {
        spawn_replies(listener, vec![(status, body)])
    }

    fn build_authority(
        runtime: &tokio::runtime::Runtime,
        listener: &TcpListener,
    ) -> Result<RemoteAgentSessionAuthority, Box<dyn std::error::Error>> {
        Ok(RemoteAgentSessionAuthority::new(
            runtime.handle().clone(),
            listener.local_addr()?,
            "test-service-bearer",
            Duration::from_secs(5),
        )?)
    }

    fn open_session(
        id: u128,
        principal: AuthenticatedPrincipal,
    ) -> Result<RegisteredAgentSession, Box<dyn std::error::Error>> {
        Ok(RegisteredAgentSession::open(
            AgentSessionId::from_uuid(Uuid::from_u128(id)),
            AgentSessionOpenRequestId::from_uuid(Uuid::from_u128(id + 100)),
            principal,
            TimestampMillis::new(1)?,
        ))
    }

    #[test]
    fn loopback_typed_reply_and_fresh_closed_reply_are_typed()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Runtime::new()?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let principal =
            AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_u128(2)));
        let session = open_session(1, principal)?;
        let closed = session.close(session.revision(), TimestampMillis::new(2)?)?;
        let open_reply = RemoteSessionResolveReply::from_session(Some(&session))?;
        let closed_reply = RemoteSessionResolveReply::from_session(Some(&closed))?;
        let server = spawn_replies(
            listener.try_clone()?,
            vec![
                (200, serde_json::to_vec(&open_reply)?),
                (200, serde_json::to_vec(&closed_reply)?),
            ],
        )?;
        let authority = build_authority(&runtime, &listener)?;
        let resolved = authority.resolve(request(session.id(), principal))?;
        assert_eq!(resolved, Some(session.clone()));
        assert_eq!(
            authority.resolve(request(session.id(), principal))?,
            Some(closed)
        );
        let open_result = authority.open(&OpenAgentSession::new(
            session.id(),
            session.request_id(),
            principal,
            TimestampMillis::new(1)?,
        ));
        assert_eq!(
            open_result.err().map(|error| error.code()),
            Some(ControlErrorCode::AgentSessionConflict)
        );
        server.join()?;
        Ok(())
    }

    #[test]
    fn wrong_identity_reply_is_conflict_and_failure_is_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Runtime::new()?;
        let principal =
            AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_u128(12)));
        let requested = open_session(11, principal)?;
        let wrong = open_session(13, principal)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let reply = RemoteSessionResolveReply::from_session(Some(&wrong))?;
        let server = spawn_reply(listener.try_clone()?, 200, serde_json::to_vec(&reply)?)?;
        let authority = build_authority(&runtime, &listener)?;
        assert_eq!(
            authority
                .resolve(request(requested.id(), principal))
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::AgentSessionConflict)
        );
        server.join()?;

        let unavailable_listener = TcpListener::bind(("127.0.0.1", 0))?;
        let open_reply = RemoteSessionResolveReply::from_session(Some(&requested))?;
        let server = spawn_reply(
            unavailable_listener.try_clone()?,
            200,
            serde_json::to_vec(&open_reply)?,
        )?;
        let unavailable = build_authority(&runtime, &unavailable_listener)?;
        assert_eq!(
            unavailable.resolve(request(requested.id(), principal))?,
            Some(requested.clone())
        );
        server.join()?;
        drop(unavailable_listener);
        assert_eq!(
            unavailable
                .resolve(request(requested.id(), principal))
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::AgentSessionAuthorityUnavailable)
        );
        Ok(())
    }
}
