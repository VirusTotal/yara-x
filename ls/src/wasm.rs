//! Wasm-specific entry point for the YARA language server.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream, StreamExt};
use futures::io::{AsyncRead, AsyncWrite};
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
        if !self.buffer.is_empty() {
            let len = std::cmp::min(buf.len(), self.buffer.len());
            buf[..len].copy_from_slice(&self.buffer[..len]);
            self.buffer.drain(..len);
            return Poll::Ready(Ok(len));
        }

        match self.stream.poll_next_unpin(cx) {
            Poll::Ready(Some(WsMessage::Binary(data))) => {
                let len = std::cmp::min(buf.len(), data.len());
                buf[..len].copy_from_slice(&data[..len]);
                self.buffer.extend_from_slice(&data[len..]);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Some(WsMessage::Text(text))) => {
                let data = text.as_bytes();
                let len = std::cmp::min(buf.len(), data.len());
                buf[..len].copy_from_slice(&data[..len]);
                self.buffer.extend_from_slice(&data[len..]);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct WsWriter<S> {
    sink: S,
}

impl<S: Sink<WsMessage, Error = WsErr> + Unpin> AsyncWrite for WsWriter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.sink).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = WsMessage::Binary(buf.to_vec());
                if let Err(e) = Pin::new(&mut self.sink).start_send(msg) {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.sink).poll_flush(cx).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.sink).poll_close(cx).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

#[wasm_bindgen(js_name = "runServer")]
pub async fn run_server(url: String) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    let (_ws, wsio) = WsMeta::connect(&url, None).await.map_err(|e| JsValue::from(e.to_string()))?;

    let (sink, stream) = wsio.split();

    let input = WsReader { stream, buffer: Vec::new() };
    let output = WsWriter { sink };

    spawn_local(async move {
        if let Err(err) = crate::serve(input, output).await {
            // Handle error, e.g., by logging to the console.
            web_sys::console::error_1(&err.to_string().into());
        }
    });

    Ok(())
}
