use std::io::{self, Write};

use crossterm::tty::IsTty;
use unicode_width::UnicodeWidthChar;

/// DEC Private Mode 2026 (Synchronized Output): tells supporting terminals to
/// buffer all writes until `END_SYNC_UPDATE` and paint the result atomically
/// in a single frame. Terminals that do not support Mode 2026 silently ignore
/// these sequences.
const BEGIN_SYNC_UPDATE: &[u8] = b"\x1b[?2026h";
const END_SYNC_UPDATE: &[u8] = b"\x1b[?2026l";

/// Trait implemented by live status views rendered by [`Console`].
pub trait Draw {
    fn draw(&self, width: usize) -> String;
}

enum PendingLine {
    Stdout(String),
    Stderr(String),
}

/// A flicker-free terminal renderer for interactive CLI commands.
///
/// Manages a transient, multi-line live status block on `stderr` while
/// allowing persistent output lines to be emitted cleanly above it on `stdout`
/// and `stderr`.
///
/// Unlike clearing every line before each redraw, status updates overwrite
/// lines in place (using `\x1b[K` to clear trailing characters on shorter
/// lines) and only clear leftover rows with `\x1b[J` when the status block
/// shrinks. All frames are wrapped in DEC Mode 2026 synchronized output
/// sequences, and persistent output lines are batched and flushed on each
/// render tick rather than clearing and redrawing the status block per line.
pub struct Console {
    /// Number of terminal rows currently occupied by the live status block.
    rendered_lines: usize,
    /// Persistent output lines queued to be printed above the status block on
    /// the next render tick or on [`Console::finish`].
    pending: Vec<PendingLine>,
}

impl Console {
    /// Creates a new [`Console`] if both `stdout` and `stderr` are attached to
    /// an interactive terminal that supports ANSI escape sequences.
    ///
    /// Returns `None` when the `stderr-logs` feature is enabled, output is
    /// redirected, or `TERM` is unset/`"dumb"`.
    pub fn new() -> Option<Self> {
        if cfg!(feature = "stderr-logs") {
            return None;
        }
        if io::stdout().is_tty()
            && io::stderr().is_tty()
            && !is_dumb_terminal()
        {
            Some(Self { rendered_lines: 0, pending: Vec::new() })
        } else {
            None
        }
    }

    /// Buffers a line to be written to `stdout` above the status block on the
    /// next [`Console::draw`] or [`Console::finish`] call.
    pub fn emit_stdout(&mut self, line: String) {
        self.pending.push(PendingLine::Stdout(line));
    }

    /// Buffers a line to be written to `stderr` above the status block on the
    /// next [`Console::draw`] or [`Console::finish`] call.
    pub fn emit_stderr(&mut self, line: String) {
        self.pending.push(PendingLine::Stderr(line));
    }

    /// Flushes any buffered output lines and renders the updated status block.
    pub fn draw<S: Draw>(&mut self, state: &S) {
        let (term_width, term_height) = crossterm::terminal::size()
            .map(|(w, h)| (w as usize, h as usize))
            .unwrap_or((80, 24));

        if self.pending.is_empty() {
            if term_width == 0 || term_height == 0 {
                return;
            }
            let mut err = io::stderr().lock();
            self.draw_status_only(state, term_width, term_height, &mut err);
        } else {
            // Lock stdout before stderr consistently to maintain a single
            // lock acquisition order.
            let mut out = io::stdout().lock();
            let mut err = io::stderr().lock();
            self.draw_to(state, term_width, term_height, &mut out, &mut err);
        }
    }

    /// Clears the live status block and flushes all remaining buffered output
    /// lines.
    pub fn finish(&mut self) {
        if self.rendered_lines == 0 && self.pending.is_empty() {
            return;
        }

        let mut out = io::stdout().lock();
        let mut err = io::stderr().lock();
        self.finish_to(&mut out, &mut err);
    }

    fn draw_status_only<S: Draw>(
        &mut self,
        state: &S,
        term_width: usize,
        term_height: usize,
        err: &mut impl Write,
    ) {
        let content = state.draw(term_width);
        if self.rendered_lines == 0 && content.lines().next().is_none() {
            return;
        }
        let mut buf = Vec::with_capacity(content.len() + 128);
        buf.extend_from_slice(BEGIN_SYNC_UPDATE);
        self.write_status_in_place(
            &mut buf,
            &content,
            term_width,
            term_height,
        );
        buf.extend_from_slice(END_SYNC_UPDATE);
        let _ = err.write_all(&buf);
        let _ = err.flush();
    }

    fn draw_to<S: Draw>(
        &mut self,
        state: &S,
        term_width: usize,
        term_height: usize,
        out: &mut impl Write,
        err: &mut impl Write,
    ) {
        if term_width == 0 || term_height == 0 {
            self.flush_pending(out, err);
            return;
        }

        if self.pending.is_empty() {
            self.draw_status_only(state, term_width, term_height, err);
            return;
        }

        let content = state.draw(term_width);

        // 1. Begin synchronized update and clear the existing status block
        //    so emitted lines start cleanly at the top row of the block.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(BEGIN_SYNC_UPDATE);
        self.write_clear_status(&mut buf);
        let _ = err.write_all(&buf);
        let _ = err.flush();

        // 2. Emit all buffered stdout/stderr lines in arrival order.
        self.flush_pending(out, err);

        // 3. Draw the updated status block below the emitted lines and end
        //    the synchronized update.
        buf.clear();
        self.write_status_in_place(
            &mut buf,
            &content,
            term_width,
            term_height,
        );
        buf.extend_from_slice(END_SYNC_UPDATE);
        let _ = err.write_all(&buf);
        let _ = err.flush();
    }

    fn finish_to(&mut self, out: &mut impl Write, err: &mut impl Write) {
        if self.rendered_lines > 0 {
            let mut buf = Vec::with_capacity(32);
            buf.extend_from_slice(BEGIN_SYNC_UPDATE);
            self.write_clear_status(&mut buf);
            let _ = err.write_all(&buf);
            let _ = err.flush();

            self.flush_pending(out, err);

            let _ = err.write_all(END_SYNC_UPDATE);
            let _ = err.flush();
        } else {
            self.flush_pending(out, err);
        }
    }

    /// Appends the escape sequences to erase the currently rendered status
    /// block and return the cursor to column 0 of its first row.
    fn write_clear_status(&mut self, buf: &mut Vec<u8>) {
        if self.rendered_lines == 0 {
            return;
        }
        if self.rendered_lines > 1 {
            let _ = write!(buf, "\x1b[{}A", self.rendered_lines - 1);
        }
        buf.extend_from_slice(b"\r\x1b[J");
        self.rendered_lines = 0;
    }

    /// Appends the escape sequences to render `content` over the existing
    /// status block in place, updating `self.rendered_lines`.
    ///
    /// Invariant: when `self.rendered_lines > 0`, the cursor rests at column 0
    /// of the last rendered row (`pending_wrap = false`).
    fn write_status_in_place(
        &mut self,
        buf: &mut Vec<u8>,
        content: &str,
        term_width: usize,
        term_height: usize,
    ) {
        let lines: Vec<&str> = content.lines().take(term_height).collect();
        let new_lines = lines.len();
        let prev_lines = self.rendered_lines;

        if new_lines == 0 {
            self.write_clear_status(buf);
            return;
        }

        if prev_lines > 1 {
            let _ = write!(buf, "\x1b[{}A", prev_lines - 1);
        }
        if prev_lines > 0 {
            buf.push(b'\r');
        }

        for (idx, line) in lines.iter().enumerate() {
            let written_width = write_truncated_line(buf, line, term_width);
            // Only erase to end-of-line when the line did not fill the entire
            // terminal width. When `written_width == term_width`, the cursor
            // sits on the rightmost column in VT100 delayed-wrap state, where
            // `\x1b[K` would erase that last character.
            if written_width < term_width {
                buf.extend_from_slice(b"\x1b[K");
            }
            if idx + 1 < new_lines {
                buf.extend_from_slice(b"\r\n");
            }
        }

        if new_lines < prev_lines && new_lines < term_height {
            // Erase leftover lines from the previous taller frame without
            // scrolling, then move back up to the last line of the new frame.
            buf.extend_from_slice(b"\r\n\x1b[J\x1b[1A");
        } else {
            // Return cursor to column 0 (canceling any delayed-wrap state).
            buf.push(b'\r');
        }

        self.rendered_lines = new_lines;
    }

    /// Flushes all buffered output lines to `stdout` and `stderr`, coalescing
    /// consecutive lines targeting the same stream while preserving ordering
    /// across streams.
    fn flush_pending(&mut self, out: &mut impl Write, err: &mut impl Write) {
        if self.pending.is_empty() {
            return;
        }

        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();

        for item in self.pending.drain(..) {
            match item {
                PendingLine::Stdout(s) => {
                    if !err_buf.is_empty() {
                        let _ = err.write_all(&err_buf);
                        let _ = err.flush();
                        err_buf.clear();
                    }
                    out_buf.extend_from_slice(s.as_bytes());
                    out_buf.push(b'\n');
                }
                PendingLine::Stderr(s) => {
                    if !out_buf.is_empty() {
                        let _ = out.write_all(&out_buf);
                        let _ = out.flush();
                        out_buf.clear();
                    }
                    err_buf.extend_from_slice(s.as_bytes());
                    err_buf.push(b'\n');
                }
            }
        }

        if !out_buf.is_empty() {
            let _ = out.write_all(&out_buf);
            let _ = out.flush();
        }
        if !err_buf.is_empty() {
            let _ = err.write_all(&err_buf);
            let _ = err.flush();
        }
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.finish();
        }
    }
}

fn is_dumb_terminal() -> bool {
    #[cfg(windows)]
    let default = false;

    #[cfg(not(windows))]
    let default = true;

    match std::env::var("TERM") {
        Ok(term) => term == "dumb",
        Err(_) => default,
    }
}

/// Writes `line` into `buf`, truncating its visible display width to at most
/// `max_width` columns while preserving ANSI escape sequences.
///
/// Returns the exact visible display width written (`<= max_width`).
fn write_truncated_line(
    buf: &mut Vec<u8>,
    line: &str,
    max_width: usize,
) -> usize {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut width = 0;
    let mut has_ansi = false;
    let mut truncated = false;

    while i < bytes.len() {
        if bytes[i] == 0x1b {
            if let Some(seq_len) = ansi_escape_len(&bytes[i..]) {
                buf.extend_from_slice(&bytes[i..i + seq_len]);
                has_ansi = true;
                i += seq_len;
                continue;
            }
            // Skip stray ESC bytes so they cannot corrupt terminal state.
            i += 1;
            continue;
        }

        let ch = line[i..].chars().next().unwrap();
        let ch_len = ch.len_utf8();
        i += ch_len;

        if ch == '\t' {
            if width + 1 > max_width {
                truncated = true;
                break;
            }
            buf.push(b' ');
            width += 1;
            continue;
        }

        let Some(ch_width) = ch.width() else {
            // Skip control characters so they cannot move the cursor.
            continue;
        };

        if width + ch_width > max_width {
            truncated = true;
            break;
        }

        buf.extend_from_slice(&bytes[i - ch_len..i]);
        width += ch_width;
    }

    if truncated && has_ansi {
        buf.extend_from_slice(b"\x1b[0m");
    }

    width
}

/// Returns the byte length of an ANSI CSI or OSC escape sequence at the start
/// of `bytes`, or `None` if `bytes` does not start with a recognized sequence.
fn ansi_escape_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 || bytes[0] != 0x1b {
        return None;
    }
    match bytes[1] {
        // CSI: ESC [ <params 0x30..=0x3F>* <interm 0x20..=0x2F>* <final 0x40..=0x7E>
        b'[' => {
            let mut j = 2;
            while j < bytes.len() && (0x30..=0x3F).contains(&bytes[j]) {
                j += 1;
            }
            while j < bytes.len() && (0x20..=0x2F).contains(&bytes[j]) {
                j += 1;
            }
            if j < bytes.len() && (0x40..=0x7E).contains(&bytes[j]) {
                Some(j + 1)
            } else {
                None
            }
        }
        // OSC: ESC ] ... (BEL | ESC \)
        b']' => {
            let mut j = 2;
            while j < bytes.len() {
                if bytes[j] == 0x07 {
                    return Some(j + 1);
                }
                if bytes[j] == 0x1b
                    && j + 1 < bytes.len()
                    && bytes[j + 1] == b'\\'
                {
                    return Some(j + 2);
                }
                j += 1;
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_test_console() -> Console {
        Console { rendered_lines: 0, pending: Vec::new() }
    }

    #[test]
    fn truncate_plain_and_exact_width() {
        let mut buf = Vec::new();
        assert_eq!(write_truncated_line(&mut buf, "hello", 10), 5);
        assert_eq!(buf, b"hello");

        buf.clear();
        assert_eq!(write_truncated_line(&mut buf, "hello", 5), 5);
        assert_eq!(buf, b"hello");

        buf.clear();
        assert_eq!(write_truncated_line(&mut buf, "hello world", 5), 5);
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn truncate_preserves_ansi_and_resets_on_clip() {
        let styled = "\x1b[1;32mhello world\x1b[0m";

        let mut buf = Vec::new();
        assert_eq!(write_truncated_line(&mut buf, styled, 11), 11);
        assert_eq!(buf, styled.as_bytes());

        buf.clear();
        assert_eq!(write_truncated_line(&mut buf, styled, 5), 5);
        assert_eq!(buf, b"\x1b[1;32mhello\x1b[0m");
    }

    #[test]
    fn truncate_wide_chars_and_control_chars() {
        // Each CJK char is 2 columns wide; with max_width=5 only 2 fit (width=4).
        let mut buf = Vec::new();
        assert_eq!(write_truncated_line(&mut buf, "你好世界", 5), 4);
        assert_eq!(String::from_utf8(buf).unwrap(), "你好");

        // Control chars are skipped, tabs become single spaces.
        let mut buf = Vec::new();
        assert_eq!(write_truncated_line(&mut buf, "a\rb\x08\tc", 10), 4);
        assert_eq!(buf, b"ab c");
    }

    #[test]
    fn render_in_place_grow_shrink_and_clear() {
        let mut console = new_test_console();
        let mut buf = Vec::new();

        // First draw: 2 lines, first fills exact width (10), second is shorter.
        console.write_status_in_place(&mut buf, "0123456789\nabc\n", 10, 24);
        assert_eq!(console.rendered_lines, 2);
        // Line 1 fills all 10 cols -> no \x1b[K; line 2 < 10 -> has \x1b[K;
        // trailing \n does not add a 3rd line.
        assert_eq!(buf, b"0123456789\r\nabc\x1b[K\r");

        // Same-height in-place update: moves up 1 line, overwrites without \x1b[2K or \x1b[J.
        buf.clear();
        console.write_status_in_place(&mut buf, "0123456789\nxyz", 10, 24);
        assert_eq!(console.rendered_lines, 2);
        assert_eq!(buf, b"\x1b[1A\r0123456789\r\nxyz\x1b[K\r");

        // Grow to 3 lines.
        buf.clear();
        console.write_status_in_place(&mut buf, "a\nb\nc", 10, 24);
        assert_eq!(console.rendered_lines, 3);
        assert_eq!(buf, b"\x1b[1A\ra\x1b[K\r\nb\x1b[K\r\nc\x1b[K\r");

        // Shrink back to 1 line: clears leftover lines below without scrolling.
        buf.clear();
        console.write_status_in_place(&mut buf, "only", 10, 24);
        assert_eq!(console.rendered_lines, 1);
        assert_eq!(buf, b"\x1b[2A\ronly\x1b[K\r\n\x1b[J\x1b[1A");

        // Single-line update must not emit `\x1b[0A`.
        buf.clear();
        console.write_status_in_place(&mut buf, "next", 10, 24);
        assert_eq!(console.rendered_lines, 1);
        assert_eq!(buf, b"\rnext\x1b[K\r");

        // Clear single line.
        buf.clear();
        console.write_clear_status(&mut buf);
        assert_eq!(console.rendered_lines, 0);
        assert_eq!(buf, b"\r\x1b[J");
    }

    #[test]
    fn shrink_clamped_to_term_height_does_not_scroll() {
        let mut console = new_test_console();
        console.rendered_lines = 5;

        let mut buf = Vec::new();
        // Terminal shrank to height 2 while drawing 3 lines -> clamped to 2.
        console.write_status_in_place(&mut buf, "a\nb\nc", 10, 2);
        assert_eq!(console.rendered_lines, 2);
        assert_eq!(buf, b"\x1b[4A\ra\x1b[K\r\nb\x1b[K\r");

        // Clear so Drop doesn't write to stderr during test.
        console.rendered_lines = 0;
    }

    struct StaticDraw(&'static str);

    impl Draw for StaticDraw {
        fn draw(&self, _width: usize) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn batched_draw_and_finish_with_synchronized_output() {
        use std::cell::RefCell;
        use std::rc::Rc;

        #[derive(Clone)]
        struct SharedBuf(Rc<RefCell<Vec<u8>>>);

        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let combined = SharedBuf(Rc::new(RefCell::new(Vec::new())));
        let mut out = combined.clone();
        let mut err = combined.clone();

        let mut console = new_test_console();

        // 1. Initial status render with no pending output.
        console.draw_to(&StaticDraw("s1\ns2"), 10, 24, &mut out, &mut err);
        assert_eq!(
            combined.0.borrow().as_slice(),
            b"\x1b[?2026hs1\x1b[K\r\ns2\x1b[K\r\x1b[?2026l"
        );
        combined.0.borrow_mut().clear();

        // 2. Emit multiple stdout + stderr messages, then a single draw tick.
        //    Expect ONE clear, all messages in arrival order with `\n`, and ONE redraw.
        console.emit_stdout("match1".into());
        console.emit_stdout("match2".into());
        console.emit_stderr("err1".into());
        console.emit_stdout("match3".into());
        console.draw_to(&StaticDraw("s3\ns4"), 10, 24, &mut out, &mut err);
        assert_eq!(
            combined.0.borrow().as_slice(),
            b"\x1b[?2026h\x1b[1A\r\x1b[Jmatch1\nmatch2\nerr1\nmatch3\ns3\x1b[K\r\ns4\x1b[K\r\x1b[?2026l"
        );
        combined.0.borrow_mut().clear();

        // 3. Emit final message and finish: clears status block and flushes line.
        console.emit_stdout("final".into());
        console.finish_to(&mut out, &mut err);
        assert_eq!(console.rendered_lines, 0);
        assert_eq!(
            combined.0.borrow().as_slice(),
            b"\x1b[?2026h\x1b[1A\r\x1b[Jfinal\n\x1b[?2026l"
        );
    }

    #[test]
    fn finish_without_prior_draw_emits_no_escapes() {
        let mut console = new_test_console();
        let mut out = Vec::new();
        let mut err = Vec::new();

        console.emit_stdout("match1".into());
        console.finish_to(&mut out, &mut err);

        assert_eq!(out, b"match1\n");
        assert!(err.is_empty());
    }
}
