//! Owned, bounded HTTP/1 sockets over the existing Axum application.

use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::Sleep;

use super::AppState;
use crate::config::{MAX_HTTP_HEADER_BYTES, MAX_HTTP_HEADERS};

pub(super) const WRITE_IDLE_DEADLINE: Duration = Duration::from_secs(5);

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConnectionStats {
    pub active: usize,
    pub admitted: usize,
    pub rejected: usize,
    pub transport_failures: usize,
}

#[derive(Debug, Default)]
pub(super) struct ConnectionMetrics {
    active: AtomicUsize,
    admitted: AtomicUsize,
    rejected: AtomicUsize,
    transport_failures: AtomicUsize,
}

impl ConnectionMetrics {
    pub(super) fn snapshot(&self) -> HttpConnectionStats {
        HttpConnectionStats {
            active: self.active.load(Ordering::Acquire),
            admitted: self.admitted.load(Ordering::Acquire),
            rejected: self.rejected.load(Ordering::Acquire),
            transport_failures: self.transport_failures.load(Ordering::Acquire),
        }
    }
}

struct ActiveConnection(Arc<ConnectionMetrics>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) async fn run(listener: TcpListener, app: Router, state: AppState) -> io::Result<()> {
    let mut connections = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            () = state.shutdown.cancelled() => break,
            joined = connections.join_next(), if !connections.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    failure = Some(io::Error::other("HTTP connection task failed"));
                    state.stop_admission();
                    state.shutdown.cancel();
                    break;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => {
                    if connections.len() >= state.config.http_connection_limit() {
                        state.connection_metrics.rejected.fetch_add(1, Ordering::AcqRel);
                        drop(stream);
                        continue;
                    }
                    let metrics = Arc::clone(&state.connection_metrics);
                    metrics.active.fetch_add(1, Ordering::AcqRel);
                    metrics.admitted.fetch_add(1, Ordering::AcqRel);
                    let guard = ActiveConnection(metrics);
                    let state = state.clone();
                    let app = app.clone();
                    connections.spawn(async move {
                        let _guard = guard;
                        serve_connection(stream, app, state).await;
                    });
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) => {}
                Err(error) => {
                    failure = Some(error);
                    state.stop_admission();
                    state.shutdown.cancel();
                    break;
                }
            },
        }
    }
    drop(listener);
    // Retain the server owner until all sockets and response bodies settle.
    // The root's observation budget may expire; it retains this join handle.
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            failure = Some(io::Error::other("HTTP connection task failed"));
        }
    }
    failure.map_or(Ok(()), Err)
}

async fn serve_connection(stream: TcpStream, app: Router, state: AppState) {
    let io = TokioIo::new(WriteDeadlineStream {
        stream,
        stalled: None,
        write_idle_deadline: WRITE_IDLE_DEADLINE,
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(state.config.http_input_deadline())
        .max_headers(MAX_HTTP_HEADERS)
        .max_buf_size(MAX_HTTP_HEADER_BYTES);
    let connection = builder.serve_connection(io, TowerToHyperService::new(app));
    tokio::pin!(connection);
    let result = tokio::select! {
        biased;
        () = state.shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
        result = &mut connection => result,
    };
    if result.is_err() {
        // Peer disconnect, parser/deadline and slow-writer failures close one
        // socket. They are observable but do not fail the whole backend.
        state
            .connection_metrics
            .transport_failures
            .fetch_add(1, Ordering::AcqRel);
    }
}

/// Bound a peer that stops consuming output without limiting an SSE stream's
/// total lifetime. No application effect or blocking task is aborted here.
struct WriteDeadlineStream<I> {
    stream: I,
    stalled: Option<Pin<Box<Sleep>>>,
    write_idle_deadline: Duration,
}

impl<I> WriteDeadlineStream<I> {
    fn bound_write<T>(
        &mut self,
        context: &mut Context<'_>,
        result: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if result.is_ready() {
            self.stalled = None;
            return result;
        }
        let timer = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.write_idle_deadline)));
        if std::future::Future::poll(timer.as_mut(), context).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP response write stalled",
            )));
        }
        Poll::Pending
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for WriteDeadlineStream<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for WriteDeadlineStream<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(context, bytes);
        self.bound_write(context, result)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        // An empty flush is not progress on a stalled write. In production
        // the inner TcpStream flush/shutdown are nonblocking operations.
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write_vectored(context, bytes);
        self.bound_write(context, result)
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, WriteDeadlineStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn write_deadline_survives_empty_flush_and_resets_only_after_progress()
    -> Result<(), Box<dyn std::error::Error>> {
        let (writer, mut peer) = tokio::io::duplex(1);
        let mut stream = WriteDeadlineStream {
            stream: writer,
            stalled: None,
            write_idle_deadline: Duration::from_millis(30),
        };
        stream.write_all(b"a").await?;
        let pending = tokio::time::timeout(Duration::from_millis(1), stream.write_all(b"b")).await;
        assert!(pending.is_err());
        stream.flush().await?;
        let error = tokio::time::timeout(Duration::from_secs(1), stream.write_all(b"b"))
            .await?
            .err()
            .ok_or("stalled write unexpectedly completed")?;
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let mut byte = [0];
        peer.read_exact(&mut byte).await?;
        stream.write_all(b"c").await?;
        // The expired timer must not immediately fail a new stalled write.
        assert!(
            tokio::time::timeout(Duration::from_millis(1), stream.write_all(b"d"))
                .await
                .is_err()
        );
        peer.read_exact(&mut byte).await?;
        stream.write_all(b"d").await?;
        Ok(())
    }
}
