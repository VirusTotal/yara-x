// Example "text" module described in the Module's Developer Guide.
//
use crate::modules::prelude::*;
use crate::modules::protos::text::*;

use std::io;
use std::io::BufRead;

use lingua::{Language, LanguageDetectorBuilder};

/// Module's main function.
///
/// The main function is called for every file that is scanned by YARA. The
/// `#[module_main]` attribute indicates that this is the module's main
/// function. The name of the function is irrelevant, but using `main` is
/// advised for consistency.
///
/// This function must return an instance of the protobuf message indicated
/// in the `root_message` option in `text.proto`.
#[module_main]
fn main(data: &[u8]) -> Text {
    // Create an empty instance of the Text protobuf.
    let mut text_proto = Text::new();

    let mut num_lines = 0;
    let mut num_words = 0;

    // Create cursor for iterating over the lines.
    let cursor = io::Cursor::new(data);

    // Count the lines and words in the file.
    for line in cursor.lines() {
        match line {
            Ok(line) => {
                num_words += line.split_whitespace().count();
                num_lines += 1;
            }
            Err(_) => return text_proto,
        }
    }

    // Set the value for fields `num_lines` and `num_words` in the protobuf.
    text_proto.set_num_lines(num_lines as i64);
    text_proto.set_num_words(num_words as i64);

    // Return the Text proto after filling the relevant fields.
    text_proto
}

/// Function that returns the n-th line in the file.
///
/// Returns None if the file has less than n lines, which is translated in YARA
/// to an undefined value.
#[module_export]
fn get_line(ctx: &mut ScanContext, n: i64) -> Option<RuntimeString> {
    let cursor = io::Cursor::new(ctx.scanned_data());

    if let Some(Ok(line)) = cursor.lines().nth(n as usize) {
        Some(RuntimeString::new(line))
    } else {
        None
    }
}

/// Function that returns `num_words / num_lines`.
#[module_export]
fn avg_words_per_line(ctx: &mut ScanContext) -> Option<f64> {
    // Obtain a reference to the `Text` protobuf that was returned by the
    // module's main function.
    let text = ctx.module_output::<Text>()?;

    let num_lines = text.num_lines? as f64;
    let num_words = text.num_words? as f64;

    Some(num_words / num_lines)
}

/// Function that returns the language in which the text file is written.
///
/// Returns None if the language can't be determined (which in YARA is handled
/// as an undefined value), or some of the values in the Language enum.
#[module_export]
fn language(ctx: &ScanContext) -> Option<i64> {
    let data = ctx.scanned_data();
    // Use `as_bstr()` for getting the scanned data as a `&BStr` instead of a
    // a `&[u8]`. Then call `to_str` for converting the `&BStr` to `&str`. This
    // operation can fail if the scanned data is not valid UTF-8, in that case
    // returns `None`, which is interpreted as `undefined` in YARA.
    let text = data.as_bstr().to_str().ok()?;

    let detector = LanguageDetectorBuilder::from_languages(&[
        lingua::Language::English,
        lingua::Language::French,
        lingua::Language::German,
        lingua::Language::Spanish,
    ])
    .build();

    // Detect the language. Returns `None` if the language cannot be reliably
    // detected.
    let language = match detector.detect_language_of(text)? {
        lingua::Language::English => Language::English,
        lingua::Language::French => Language::French,
        lingua::Language::German => Language::German,
        lingua::Language::Spanish => Language::Spanish,
    };

    Some(language as i64)
}
