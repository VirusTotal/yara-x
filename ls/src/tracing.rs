//! Custom middleware for tracing LSP messages.
//!
//! This module provides a middleware layer that logs all incoming LSP
//! requests and notifications, including their method names and parameters.

use std::ops::ControlFlow;
use std::task::{Context, Poll};

use async_lsp::{AnyEvent, AnyNotification, AnyRequest, LspService};
use tower::{Layer, Service};

/// A middleware that traces all LSP messages by logging their method names
/// and parameters.
///
/// Unlike the built-in `TracingLayer` from `async_lsp`, this middleware
/// actively prints messages using `eprintln!` for immediate visibility.
pub struct MessageTracing<S> {
    inner: S,
}

impl<S> MessageTracing<S> {
    /// Creates a new `MessageTracing` middleware wrapping the given service.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: LspService> Service<AnyRequest> for MessageTracing<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: AnyRequest) -> Self::Future {
        eprintln!(
            "[LSP] --> Request: {} (id: {:?})\n        params: {}",
            req.method,
            req.id,
            serde_json::to_string_pretty(&req.params).unwrap_or_default()
        );
        self.inner.call(req)
    }
}

impl<S: LspService> LspService for MessageTracing<S> {
    fn notify(
        &mut self,
        notif: AnyNotification,
    ) -> ControlFlow<async_lsp::Result<()>> {
        eprintln!(
            "[LSP] --> Notification: {}\n        params: {}",
            notif.method,
            serde_json::to_string_pretty(&notif.params).unwrap_or_default()
        );
        self.inner.notify(notif)
    }

    fn emit(&mut self, event: AnyEvent) -> ControlFlow<async_lsp::Result<()>> {
        eprintln!("[LSP] --> Event: {:?}", event);
        self.inner.emit(event)
    }
}

/// A Tower `Layer` that wraps services with [`MessageTracing`].
#[derive(Clone, Default)]
pub struct MessageTracingLayer;

impl<S> Layer<S> for MessageTracingLayer {
    type Service = MessageTracing<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MessageTracing::new(inner)
    }
}
