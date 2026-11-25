use std::ffi::{CStr, c_char};
use std::io::Write;
use std::mem::ManuallyDrop;

use yara_x::mods as yrx_mods;
use yara_x_proto::json::{Format as JsonFormat, Serializer as JsonSerializer};
use yara_x_proto::yaml::Serializer as YamlSerializer;

use crate::{
    _yrx_set_last_error, YRX_BUFFER, YRX_RESULT, slice_from_ptr_and_len,
};

/// Formats in which [`yrx_modules_dump`] can render the data produced by
/// YARA modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum YRX_DUMP_FORMAT {
    /// YAML format, the default format used by the `yr dump` command.
    YRX_DUMP_YAML,
    /// JSON format, like `yr dump --output-format json`.
    YRX_DUMP_JSON,
}

/// Dumps the data produced by YARA modules for the given input data.
///
/// It behaves exactly like the `yr dump` command-line tool, and the
/// returned data is identical to the output printed by that command.
///
/// # Arguments
///
/// * `data`: pointer to the input data. It can be null if `data_len` is 0.
/// * `data_len`: length of the input data.
/// * `modules`: if not null, it is a comma-separated list of module names
///   (e.g: "pe,dotnet") and only those modules are dumped, even if they
///   didn't produce any results for the given data. If null, only the
///   modules that produced meaningful results are dumped. This is
///   equivalent to the `--module` argument of the `yr dump` command.
/// * `format`: the output format, see [`YRX_DUMP_FORMAT`].
/// * `colors`: if true, the returned data contains ANSI escape sequences
///   for showing the results in color.
/// * `buf`: address where a pointer to a [`YRX_BUFFER`] structure will be
///   copied. The buffer contains the dumped data as UTF-8 text.
///
/// The returned buffer must be destroyed with `yrx_buffer_destroy`.
///
/// # Example
///
/// ```c
/// YRX_BUFFER* buf;
/// if (yrx_modules_dump(data, len, NULL, YRX_DUMP_YAML, false, &buf) ==
///     YRX_SUCCESS) {
///     fwrite(buf->data, 1, buf->length, stdout);
///     yrx_buffer_destroy(buf);
/// }
/// ```
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yrx_modules_dump(
    data: *const u8,
    data_len: usize,
    modules: *const c_char,
    format: YRX_DUMP_FORMAT,
    colors: bool,
    buf: *mut *mut YRX_BUFFER,
) -> YRX_RESULT {
    if buf.is_null() {
        _yrx_set_last_error(Some("`buf` pointer cannot be null"));
        return YRX_RESULT::YRX_INVALID_ARGUMENT;
    }

    *buf = std::ptr::null_mut();

    let data = match slice_from_ptr_and_len(data, data_len) {
        Some(data) => data,
        None => {
            _yrx_set_last_error(Some(
                "`data` pointer cannot be null when `data_len` is greater than 0",
            ));
            return YRX_RESULT::YRX_INVALID_ARGUMENT;
        }
    };

    let mut modules_output = yrx_mods::invoke_all(data);

    // If a list of modules was passed, retain only those modules. Otherwise
    // retain only the modules that produced meaningful results.
    if modules.is_null() {
        yrx_mods::retain_meaningful(&mut modules_output);
    } else {
        let modules = match CStr::from_ptr(modules).to_str() {
            Ok(modules) => modules,
            Err(err) => {
                _yrx_set_last_error(Some(err));
                return YRX_RESULT::YRX_INVALID_UTF8;
            }
        };

        let requested = modules
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect::<Vec<&str>>();

        if requested.is_empty() {
            _yrx_set_last_error(Some(
                "`modules` must contain at least one module name",
            ));
            return YRX_RESULT::YRX_INVALID_ARGUMENT;
        }

        if let Err(err) =
            yrx_mods::retain_requested(&mut modules_output, &requested)
        {
            _yrx_set_last_error(Some(err));
            return YRX_RESULT::YRX_INVALID_ARGUMENT;
        }
    }

    // Render the modules output as text. This is the same serialization
    // performed by the `yr dump` command.
    let mut output = Vec::new();

    let result = match format {
        YRX_DUMP_FORMAT::YRX_DUMP_JSON => {
            let mut serializer = JsonSerializer::new(&mut output);
            serializer
                .with_colors(colors)
                .with_format(JsonFormat::Legacy)
                .serialize(modules_output.as_ref())
        }
        // YAML is the default format in `yr dump`.
        _ => {
            let mut serializer = YamlSerializer::new(&mut output);
            serializer.with_colors(colors).serialize(modules_output.as_ref())
        }
    };

    match result {
        Ok(()) => {
            // Like `yr dump`, the output is terminated with a newline.
            output.write_all(b"\n").unwrap();
            let output = output.into_boxed_slice();
            let mut output = ManuallyDrop::new(output);
            *buf = Box::into_raw(Box::new(YRX_BUFFER {
                data: output.as_mut_ptr(),
                length: output.len(),
            }));
            _yrx_set_last_error::<std::io::Error>(None);
            YRX_RESULT::YRX_SUCCESS
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_SERIALIZATION_ERROR
        }
    }
}
