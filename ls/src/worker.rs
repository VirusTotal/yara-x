//! Browser worker entry point for the YARA language server.

#[cfg(target_family = "wasm")]
use std::pin::Pin;
#[cfg(target_family = "wasm")]
use std::task::{Context, Poll};

#[cfg(target_family = "wasm")]
use futures::StreamExt;
#[cfg(target_family = "wasm")]
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
#[cfg(target_family = "wasm")]
use futures::io::{AsyncRead, AsyncWrite};
#[cfg(target_family = "wasm")]
use js_sys::JSON;
#[cfg(target_family = "wasm")]
use wasm_bindgen::JsCast;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(target_family = "wasm")]
use wasm_bindgen_futures::spawn_local;
#[cfg(target_family = "wasm")]
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

#[cfg(target_family = "wasm")]
struct WorkerReader {
    receiver: UnboundedReceiver<Vec<u8>>,
    buffer: Vec<u8>,
}

#[cfg(target_family = "wasm")]
struct WorkerWriter {
    scope: DedicatedWorkerGlobalScope,
    buffer: Vec<u8>,
}

#[cfg(target_family = "wasm")]
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

#[cfg(target_family = "wasm")]
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

#[cfg(target_family = "wasm")]
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
#[cfg(target_family = "wasm")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_lsp_message() {
        let mut buf = Vec::new();
        push_lsp_message(&mut buf, b"hello");
        assert_eq!(buf, b"Content-Length: 5\r\n\r\nhello");
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(
            find_header_end(b"Content-Length: 10\r\n\r\nbody"),
            Some(18)
        );
        assert_eq!(find_header_end(b"Content-Length: 10\r\n"), None);
        assert_eq!(find_header_end(b"short"), None);
    }

    #[test]
    fn test_parse_content_length() {
        assert_eq!(parse_content_length(b"Content-Length: 42"), Some(42));
        assert_eq!(
            parse_content_length(b"content-length: 100\r\nOther: foo"),
            Some(100)
        );
        assert_eq!(parse_content_length(b"Content-Length: abc"), None);
        assert_eq!(parse_content_length(b"Other: 10"), None);
    }

    #[test]
    fn test_take_lsp_message() {
        let mut buf = Vec::new();
        assert_eq!(take_lsp_message(&mut buf), None);

        // Incomplete body
        buf.extend_from_slice(b"Content-Length: 10\r\n\r\nshort");
        assert_eq!(take_lsp_message(&mut buf), None);

        // Complete message
        buf.extend_from_slice(b"body!");
        assert_eq!(take_lsp_message(&mut buf), Some("shortbody!".to_string()));
        assert!(buf.is_empty());

        // Chained messages
        buf.extend_from_slice(
            b"Content-Length: 3\r\n\r\nfooContent-Length: 3\r\n\r\nbar",
        );
        assert_eq!(take_lsp_message(&mut buf), Some("foo".to_string()));
        assert_eq!(take_lsp_message(&mut buf), Some("bar".to_string()));
        assert!(buf.is_empty());
    }
}
