//! Browser worker entry point for the YARA language server.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use futures::io::{AsyncRead, AsyncWrite};
use js_sys::JSON;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

struct WorkerReader {
    receiver: UnboundedReceiver<Vec<u8>>,
    buffer: Vec<u8>,
}

struct WorkerWriter {
    scope: DedicatedWorkerGlobalScope,
    buffer: Vec<u8>,
}

impl AsyncRead for WorkerReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.is_empty() {
            match self.receiver.poll_next_unpin(cx) {
                Poll::Ready(Some(data)) => {
                    push_lsp_message(&mut self.buffer, &data);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let len = buf.len().min(self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);

        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for WorkerWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buffer.extend_from_slice(buf);

        while let Some(text) = take_lsp_message(&mut self.buffer) {
            let payload = JSON::parse(&text)
                .unwrap_or_else(|_| JsValue::from_str(&text));

            self.scope
                .post_message(&payload)
                .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn push_lsp_message(buffer: &mut Vec<u8>, body: &[u8]) {
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    buffer.extend_from_slice(header.as_bytes());
    buffer.extend_from_slice(body);
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }

    None
}

fn parse_content_length(header_buf: &[u8]) -> Option<usize> {
    let header_str = std::str::from_utf8(header_buf).ok()?;

    for line in header_str.lines() {
        let (name, value) = line.split_once(':')?;

        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }

    None
}

fn take_lsp_message(buffer: &mut Vec<u8>) -> Option<String> {
    let header_end = find_header_end(buffer)?;
    let content_length = parse_content_length(&buffer[..header_end])?;
    let total_required = header_end + 4 + content_length;

    if buffer.len() < total_required {
        return None;
    }

    let body = buffer[header_end + 4..total_required].to_vec();
    buffer.drain(..total_required);

    Some(String::from_utf8_lossy(&body).into_owned())
}

fn event_data_as_text(event: &MessageEvent) -> Option<String> {
    if let Some(text) = event.data().as_string() {
        return Some(text);
    }

    JSON::stringify(&event.data()).ok().and_then(|value| value.as_string())
}

/// Starts the language server inside a browser dedicated worker.
///
/// Messages received through `postMessage` are adapted to the LSP
/// `Content-Length` framing expected by [`crate::serve`]. Outgoing LSP
/// messages are parsed and posted back as JSON values when possible, or
/// as raw strings otherwise.
#[wasm_bindgen(js_name = "runWorkerServer")]
pub fn run_worker_server() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    let scope: DedicatedWorkerGlobalScope =
        js_sys::global().dyn_into().map_err(|_| {
            JsValue::from_str(
                "runWorkerServer must be called from a dedicated worker",
            )
        })?;

    let (sender, receiver) = unbounded::<Vec<u8>>();

    let onmessage =
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(text) = event_data_as_text(&event) {
                let _ = sender.unbounded_send(text.into_bytes());
            }
        });

    scope.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    let input = WorkerReader { receiver, buffer: Vec::new() };
    let output = WorkerWriter { scope, buffer: Vec::new() };

    spawn_local(async move {
        if let Err(err) = crate::serve(input, output).await {
            web_sys::console::error_1(&JsValue::from_str(&err.to_string()));
        }
    });

    Ok(())
}
