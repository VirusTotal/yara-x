//! Wasm-specific entry point for the YARA language server.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use futures::{Sink, Stream, StreamExt};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::*;

struct WsReader<S> {
    stream: S,
    buffer: Vec<u8>,
}

impl<S: Stream<Item = WsMessage> + Unpin> AsyncRead for WsReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.is_empty() {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => {
                    let data = match msg {
                        WsMessage::Binary(d) => d,
                        WsMessage::Text(t) => t.into_bytes(),
                    };
                    web_sys::console::log_1(&format!("[Rust WsReader] Received message from WebSocket, size: {}", data.len()).into());
                    // Prepend Content-Length header for async-lsp's run_buffered
                    let header =
                        format!("Content-Length: {}\r\n\r\n", data.len());
                    self.buffer.extend_from_slice(header.as_bytes());
                    self.buffer.extend_from_slice(&data);
                }
                Poll::Ready(None) => {
                    web_sys::console::log_1(
                        &"[Rust WsReader] WebSocket stream closed".into(),
                    );
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Poll::Ready(Ok(len))
    }
}

struct WsWriter<S> {
    sink: S,
    buffer: Vec<u8>,
}

impl<S: Sink<WsMessage, Error = WsErr> + Unpin> AsyncWrite for WsWriter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Collect bytes in a buffer until we have a full LSP message
        self.buffer.extend_from_slice(buf);

        // Try to find the end of the header
        if let Some(pos) = self.find_header_end(&self.buffer) {
            // We found \r\n\r\n. Now we need to know the Content-Length to see if we have the full body.
            if let Some(content_length) =
                self.parse_content_length(&self.buffer[..pos])
            {
                let total_required = pos + 4 + content_length;
                if self.buffer.len() >= total_required {
                    web_sys::console::log_1(&format!("[Rust WsWriter] Sending full LSP message to WebSocket, body size: {}", content_length).into());
                    // We have a full message! Send only the body to the WebSocket.
                    match Pin::new(&mut self.sink).poll_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            let body =
                                self.buffer[pos + 4..total_required].to_vec();
                            let text =
                                String::from_utf8_lossy(&body).into_owned();
                            if let Err(e) = Pin::new(&mut self.sink)
                                .start_send(WsMessage::Text(text))
                            {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    e.to_string(),
                                )));
                            }
                            // Drain the processed message
                            self.buffer.drain(..total_required);
                            return Poll::Ready(Ok(buf.len()));
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e.to_string(),
                            )));
                        }
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                    }
                }
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.sink).poll_flush(cx).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.sink).poll_close(cx).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
}

impl<S> WsWriter<S> {
    fn find_header_end(&self, buf: &[u8]) -> Option<usize> {
        for i in 0..buf.len().saturating_sub(3) {
            if &buf[i..i + 4] == b"\r\n\r\n" {
                return Some(i);
            }
        }
        None
    }

    fn parse_content_length(&self, header_buf: &[u8]) -> Option<usize> {
        let header_str = std::str::from_utf8(header_buf).ok()?;
        for line in header_str.lines() {
            if line.to_lowercase().starts_with("content-length:") {
                return line.split(':').nth(1)?.trim().parse().ok();
            }
        }
        None
    }
}

#[wasm_bindgen(js_name = "runServer")]
pub async fn run_server(url: String) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    let (_ws, wsio) = WsMeta::connect(&url, None)
        .await
        .map_err(|e| JsValue::from(e.to_string()))?;

    let (sink, stream) = wsio.split();

    let input = WsReader { stream, buffer: Vec::new() };
    let output = WsWriter { sink, buffer: Vec::new() };

    spawn_local(async move {
        if let Err(err) = crate::serve(input, output).await {
            // Handle error, e.g., by logging to the console.
            web_sys::console::error_1(&err.to_string().into());
        }
    });

    Ok(())
}
