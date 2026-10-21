//! Bounded input acquisition. These deadlines never wrap admitted effects.

use std::error::Error;

use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use super::AppState;
use crate::{ForgeError, config::MAX_BODY_BYTES};

pub(super) async fn acquire_body(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    if body.is_end_stream() {
        return next.run(Request::from_parts(parts, body)).await;
    }
    let read = to_bytes(body, MAX_BODY_BYTES);
    let bytes = tokio::select! {
        biased;
        () = state.shutdown.cancelled() => return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            &ForgeError::capacity_exceeded("HTTP ingress (shutting down)"),
        ),
        result = tokio::time::timeout(state.config.http_input_deadline(), read) => match result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => {
                let oversized = error.source().is_some_and(
                    <dyn Error>::is::<http_body_util::LengthLimitError>);
                return failure(
                    if oversized { StatusCode::PAYLOAD_TOO_LARGE } else { StatusCode::BAD_REQUEST },
                    &ForgeError::invalid_input("the HTTP request body is invalid or oversized"),
                );
            }
            Err(_) => return failure(StatusCode::REQUEST_TIMEOUT,
                &ForgeError::invalid_input("the HTTP request body acquisition deadline expired")),
        },
    };
    // No application operation has started while input is acquired. A
    // shutdown race after this point is fenced again by command admission.
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn failure(status: StatusCode, error: &ForgeError) -> Response {
    let mut response = super::reject(None, error);
    *response.status_mut() = status;
    // Discarding incomplete input cannot safely reuse an HTTP/1 connection.
    response.headers_mut().insert(
        header::CONNECTION,
        axum::http::HeaderValue::from_static("close"),
    );
    response
}
