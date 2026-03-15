#![allow(non_camel_case_types)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::alloc::{alloc, dealloc, realloc, Layout};
use std::mem::{self, ManuallyDrop};
use std::ptr;
use std::ptr::slice_from_raw_parts_mut;
use std::slice;
use std::sync::Arc;

use base64::Engine as _;
use serde::Serialize;
use serde_json::Value as JsonValue;
use yara_x::blocks;
use yara_x::MetaValue;
use yara_x::Pattern;
use yara_x::Rule;
use yara_x::SourceCode;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum YRX_RESULT {
    YRX_SUCCESS,
    YRX_SYNTAX_ERROR,
    YRX_VARIABLE_ERROR,
    YRX_SCAN_ERROR,
    YRX_SCAN_TIMEOUT,
    YRX_INVALID_ARGUMENT,
    YRX_INVALID_UTF8,
    YRX_INVALID_STATE,
    YRX_SERIALIZATION_ERROR,
    YRX_NO_METADATA,
    YRX_NOT_SUPPORTED,
}

const YRX_COLORIZE_ERRORS: u32 = 1;
const YRX_RELAXED_RE_SYNTAX: u32 = 2;
const YRX_ERROR_ON_SLOW_PATTERN: u32 = 4;
const YRX_ERROR_ON_SLOW_LOOP: u32 = 8;
const YRX_ENABLE_CONDITION_OPTIMIZATION: u32 = 16;
const YRX_DISABLE_INCLUDES: u32 = 32;

const GO_YRX_ABI_VERSION: u32 = 6;

#[repr(C)]
pub struct YRX_BUFFER {
    pub data: *mut u8,
    pub length: usize,
}

impl Drop for YRX_BUFFER {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(slice_from_raw_parts_mut(
                self.data,
                self.length,
            )));
        }
    }
}

struct CompilerState {
    flags: u32,
    inner: yara_x::Compiler<'static>,
}

struct RulesInner {
    rules: yara_x::Rules,
}

struct RulesState {
    inner: Arc<RulesInner>,
}

struct ScannerState {
    _rules: Arc<RulesInner>,
    inner: Option<yara_x::Scanner<'static>>,
}

impl Drop for ScannerState {
    fn drop(&mut self) {
        let _ = self.inner.take();
    }
}

impl ScannerState {
    fn inner_ref(&self) -> Result<&yara_x::Scanner<'static>, String> {
        self.inner
            .as_ref()
            .ok_or_else(|| "scanner already destroyed".to_string())
    }

    fn inner_mut(&mut self) -> Result<&mut yara_x::Scanner<'static>, String> {
        self.inner
            .as_mut()
            .ok_or_else(|| "scanner already destroyed".to_string())
    }
}

struct BlockScannerState {
    _rules: Arc<RulesInner>,
    inner: Option<blocks::Scanner<'static>>,
}

impl Drop for BlockScannerState {
    fn drop(&mut self) {
        let _ = self.inner.take();
    }
}

impl BlockScannerState {
    fn inner_mut(&mut self) -> Result<&mut blocks::Scanner<'static>, String> {
        self.inner
            .as_mut()
            .ok_or_else(|| "block scanner already destroyed".to_string())
    }
}

#[derive(Clone, Serialize)]
struct RuleJson {
    #[serde(rename = "n")]
    namespace: String,
    #[serde(rename = "i")]
    identifier: String,
    #[serde(rename = "t")]
    tags: Vec<String>,
    #[serde(rename = "p")]
    patterns: Vec<PatternJson>,
    #[serde(rename = "m")]
    metadata: Vec<MetadataJson>,
}

#[derive(Clone, Serialize)]
struct PatternJson {
    #[serde(rename = "i")]
    identifier: String,
    #[serde(rename = "m")]
    matches: Vec<MatchJson>,
}

#[derive(Clone, Serialize)]
struct MatchJson {
    #[serde(rename = "o")]
    offset: u64,
    #[serde(rename = "l")]
    length: u64,
}

#[derive(Clone, Serialize)]
struct MetadataJson {
    #[serde(rename = "i")]
    identifier: String,
    #[serde(rename = "v")]
    value: MetadataValueJson,
}

#[derive(Clone, Serialize)]
#[serde(tag = "k", content = "v")]
enum MetadataValueJson {
    #[serde(rename = "i")]
    Int(i64),
    #[serde(rename = "f")]
    Float(f64),
    #[serde(rename = "b")]
    Bool(bool),
    #[serde(rename = "s")]
    String(String),
    #[serde(rename = "x")]
    Bytes(String),
}

#[derive(Serialize)]
struct ProfilingInfoJson {
    #[serde(rename = "n")]
    namespace: String,
    #[serde(rename = "r")]
    rule: String,
    #[serde(rename = "p")]
    pattern_matching_time: f64,
    #[serde(rename = "c")]
    condition_exec_time: f64,
}

fn create_compiler(flags: u32) -> yara_x::Compiler<'static> {
    let mut compiler = yara_x::Compiler::new();
    if flags & YRX_RELAXED_RE_SYNTAX != 0 {
        compiler.relaxed_re_syntax(true);
    }
    if flags & YRX_ENABLE_CONDITION_OPTIMIZATION != 0 {
        compiler.condition_optimization(true);
    }
    if flags & YRX_COLORIZE_ERRORS != 0 {
        compiler.colorize_errors(true);
    }
    if flags & YRX_ERROR_ON_SLOW_PATTERN != 0 {
        compiler.error_on_slow_pattern(true);
    }
    if flags & YRX_ERROR_ON_SLOW_LOOP != 0 {
        compiler.error_on_slow_loop(true);
    }
    if flags & YRX_DISABLE_INCLUDES != 0 {
        compiler.enable_includes(false);
    }
    compiler
}

fn pack_result(code: YRX_RESULT, payload: u32) -> u64 {
    ((code as u64) << 32) | payload as u64
}

fn success_result(payload: u32) -> u64 {
    pack_result(YRX_RESULT::YRX_SUCCESS, payload)
}

fn error_buffer_handle(message: impl ToString) -> u32 {
    buffer_from_bytes(message.to_string().into_bytes()) as u32
}

fn error_result(code: YRX_RESULT, message: impl ToString) -> u64 {
    if matches!(code, YRX_RESULT::YRX_SCAN_TIMEOUT) {
        pack_result(code, 0)
    } else {
        pack_result(code, error_buffer_handle(message))
    }
}

fn structured_error_result<T: Serialize + ?Sized>(
    code: YRX_RESULT,
    value: &T,
) -> u64 {
    match serialize_to_buffer(value) {
        Ok(handle) => pack_result(code, handle),
        Err(err) => error_result(YRX_RESULT::YRX_SERIALIZATION_ERROR, err),
    }
}

fn serialize_to_buffer<T: Serialize + ?Sized>(
    value: &T,
) -> Result<u32, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| buffer_from_bytes(bytes) as u32)
}

fn serialization_result<T: Serialize + ?Sized>(value: &T) -> u64 {
    match serialize_to_buffer(value) {
        Ok(handle) => success_result(handle),
        Err(err) => error_result(YRX_RESULT::YRX_SERIALIZATION_ERROR, err),
    }
}

fn buffer_from_bytes(data: Vec<u8>) -> *mut YRX_BUFFER {
    let boxed = data.into_boxed_slice();
    let mut boxed = ManuallyDrop::new(boxed);

    Box::into_raw(Box::new(YRX_BUFFER {
        data: boxed.as_mut_ptr(),
        length: boxed.len(),
    }))
}

#[link(wasm_import_module = "go:console/host")]
unsafe extern "C" {
    #[link_name = "write-message"]
    fn go_yrx_console_write_message(
        guest_instance_id: u64,
        message_ptr: u32,
        message_len: u32,
    );
}

fn emit_console_message(guest_instance_id: u64, message: &str) {
    let Ok(message_len) = u32::try_from(message.len()) else {
        return;
    };

    unsafe {
        go_yrx_console_write_message(
            guest_instance_id,
            message.as_ptr() as usize as u32,
            message_len,
        );
    }
}

fn normalize_size(size: u32) -> usize {
    if size == 0 {
        1
    } else {
        size as usize
    }
}

fn into_handle<T>(value: T) -> u32 {
    Box::into_raw(Box::new(value)) as usize as u32
}

unsafe fn ref_from_handle<T>(handle: u32) -> Option<&'static T> {
    if handle == 0 {
        None
    } else {
        (handle as usize as *const T).as_ref()
    }
}

unsafe fn mut_from_handle<T>(handle: u32) -> Option<&'static mut T> {
    if handle == 0 {
        None
    } else {
        (handle as usize as *mut T).as_mut()
    }
}

unsafe fn destroy_handle<T>(handle: u32) {
    if handle != 0 {
        drop(Box::from_raw(handle as usize as *mut T));
    }
}

unsafe fn bytes_from_ptr_len(
    ptr: u32,
    len: u32,
) -> Result<&'static [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr == 0 {
        return Err("null pointer with non-zero length".to_string());
    }
    Ok(slice::from_raw_parts(ptr as *const u8, len as usize))
}

unsafe fn string_from_ptr_len(
    ptr: u32,
    len: u32,
) -> Result<String, YRX_RESULT> {
    let bytes = bytes_from_ptr_len(ptr, len)
        .map_err(|_| YRX_RESULT::YRX_INVALID_ARGUMENT)?;
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| YRX_RESULT::YRX_INVALID_UTF8)
}

unsafe fn optional_string_from_ptr_len(
    ptr: u32,
    len: u32,
) -> Result<Option<String>, YRX_RESULT> {
    if ptr == 0 && len == 0 {
        Ok(None)
    } else {
        string_from_ptr_len(ptr, len).map(Some)
    }
}

unsafe fn json_from_ptr_len(ptr: u32, len: u32) -> Result<JsonValue, u64> {
    let bytes = match bytes_from_ptr_len(ptr, len) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err))
        }
    };

    serde_json::from_slice(bytes)
        .map_err(|err| error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err))
}

fn usize_from_u64(value: u64, name: &str) -> Result<usize, u64> {
    usize::try_from(value).map_err(|_| {
        error_result(
            YRX_RESULT::YRX_INVALID_ARGUMENT,
            format!("{name} does not fit in usize"),
        )
    })
}

fn pattern_to_json(pattern: Pattern<'_, '_>) -> PatternJson {
    let matches = pattern
        .matches()
        .map(|m| {
            let range = m.range();
            MatchJson {
                offset: range.start as u64,
                length: (range.end - range.start) as u64,
            }
        })
        .collect();

    PatternJson { identifier: pattern.identifier().to_string(), matches }
}

fn metadata_to_json(
    (identifier, value): (&str, MetaValue<'_>),
) -> MetadataJson {
    let value = match value {
        MetaValue::Integer(v) => MetadataValueJson::Int(v),
        MetaValue::Float(v) => MetadataValueJson::Float(v),
        MetaValue::Bool(v) => MetadataValueJson::Bool(v),
        MetaValue::String(v) => MetadataValueJson::String(v.to_string()),
        MetaValue::Bytes(v) => {
            let bytes: &[u8] = v.as_ref();
            MetadataValueJson::Bytes(
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )
        }
    };

    MetadataJson { identifier: identifier.to_string(), value }
}

fn rule_to_json(rule: Rule<'_, '_>) -> RuleJson {
    RuleJson {
        namespace: rule.namespace().to_string(),
        identifier: rule.identifier().to_string(),
        tags: rule.tags().map(|tag| tag.identifier().to_string()).collect(),
        patterns: rule.patterns().map(pattern_to_json).collect(),
        metadata: rule.metadata().map(metadata_to_json).collect(),
    }
}

fn rules_to_json(rules: &yara_x::Rules) -> Vec<RuleJson> {
    rules.iter().map(rule_to_json).collect()
}

fn matching_rules_to_json(
    results: &yara_x::ScanResults<'_, '_>,
) -> Vec<RuleJson> {
    results.matching_rules().map(rule_to_json).collect()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_abi_version() -> u32 {
    GO_YRX_ABI_VERSION
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_version() -> u64 {
    success_result(
        buffer_from_bytes(yara_x::VERSION.as_bytes().to_vec()) as u32
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_buffer_ptr(handle: u32) -> u32 {
    ref_from_handle::<YRX_BUFFER>(handle)
        .map(|buffer| buffer.data as u32)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_buffer_len(handle: u32) -> u32 {
    ref_from_handle::<YRX_BUFFER>(handle)
        .map(|buffer| buffer.length as u32)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_buffer_destroy(handle: u32) {
    destroy_handle::<YRX_BUFFER>(handle);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_create(flags: u32) -> u64 {
    success_result(into_handle(CompilerState {
        flags,
        inner: create_compiler(flags),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_destroy(compiler: u32) {
    destroy_handle::<CompilerState>(compiler);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_add_source_with_origin(
    compiler: u32,
    src_ptr: u32,
    src_len: u32,
    origin_ptr: u32,
    origin_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let src = match bytes_from_ptr_len(src_ptr, src_len) {
        Ok(src) => src,
        Err(err) => {
            return error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err)
        }
    };

    let origin = match optional_string_from_ptr_len(origin_ptr, origin_len) {
        Ok(origin) => origin,
        Err(code) => {
            return error_result(code, "source origin is not valid UTF-8")
        }
    };

    let mut source = SourceCode::from(src);
    if let Some(origin) = origin.as_deref() {
        source = source.with_origin(origin);
    }

    match compiler.inner.add_source(source) {
        Ok(_) => success_result(0),
        Err(err) => {
            structured_error_result(YRX_RESULT::YRX_SYNTAX_ERROR, &err)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_add_include_dir(
    compiler: u32,
    dir_ptr: u32,
    dir_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let dir = match string_from_ptr_len(dir_ptr, dir_len) {
        Ok(dir) => dir,
        Err(code) => {
            return error_result(code, "include dir is not valid UTF-8")
        }
    };

    compiler.inner.add_include_dir(dir);
    success_result(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_ignore_module(
    compiler: u32,
    module_ptr: u32,
    module_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let module = match string_from_ptr_len(module_ptr, module_len) {
        Ok(module) => module,
        Err(code) => {
            return error_result(code, "module name is not valid UTF-8")
        }
    };

    compiler.inner.ignore_module(module);
    success_result(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_enable_feature(
    compiler: u32,
    feature_ptr: u32,
    feature_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let feature = match string_from_ptr_len(feature_ptr, feature_len) {
        Ok(feature) => feature,
        Err(code) => {
            return error_result(code, "feature name is not valid UTF-8")
        }
    };

    compiler.inner.enable_feature(feature);
    success_result(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_add_linter_rule_name(
    compiler: u32,
    regex_ptr: u32,
    regex_len: u32,
    err_on_fail: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let regex = match string_from_ptr_len(regex_ptr, regex_len) {
        Ok(regex) => regex,
        Err(code) => {
            return error_result(code, "rule-name regex is not valid UTF-8")
        }
    };

    match yara_x::linters::rule_name(regex) {
        Ok(linter) => {
            compiler.inner.add_linter(linter.error(err_on_fail != 0));
            success_result(0)
        }
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_add_linter_tags_allowed(
    compiler: u32,
    tags_ptr: u32,
    tags_len: u32,
    err_on_fail: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let tags = match bytes_from_ptr_len(tags_ptr, tags_len) {
        Ok(tags) => tags,
        Err(err) => {
            return error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err)
        }
    };

    let tags: Vec<String> = match serde_json::from_slice(tags) {
        Ok(tags) => tags,
        Err(err) => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                format!("allowed tags are not valid JSON: {err}"),
            )
        }
    };

    compiler.inner.add_linter(
        yara_x::linters::tags_allowed(tags).error(err_on_fail != 0),
    );
    success_result(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_add_linter_tag_regex(
    compiler: u32,
    regex_ptr: u32,
    regex_len: u32,
    err_on_fail: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let regex = match string_from_ptr_len(regex_ptr, regex_len) {
        Ok(regex) => regex,
        Err(code) => {
            return error_result(code, "tag regex is not valid UTF-8")
        }
    };

    match yara_x::linters::tag_regex(regex) {
        Ok(linter) => {
            compiler.inner.add_linter(linter.error(err_on_fail != 0));
            success_result(0)
        }
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_add_linter_required_metadata(
    compiler: u32,
    ident_ptr: u32,
    ident_len: u32,
    err_on_fail: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(
                code,
                "metadata identifier is not valid UTF-8",
            )
        }
    };

    compiler.inner.add_linter(
        yara_x::linters::metadata(ident)
            .required(true)
            .error(err_on_fail != 0),
    );
    success_result(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_ban_module(
    compiler: u32,
    module_ptr: u32,
    module_len: u32,
    title_ptr: u32,
    title_len: u32,
    message_ptr: u32,
    message_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let module = match string_from_ptr_len(module_ptr, module_len) {
        Ok(module) => module,
        Err(code) => {
            return error_result(code, "module name is not valid UTF-8")
        }
    };
    let title = match string_from_ptr_len(title_ptr, title_len) {
        Ok(title) => title,
        Err(code) => return error_result(code, "title is not valid UTF-8"),
    };
    let message = match string_from_ptr_len(message_ptr, message_len) {
        Ok(message) => message,
        Err(code) => {
            return error_result(code, "error message is not valid UTF-8")
        }
    };

    compiler.inner.ban_module(module, title, message);
    success_result(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_new_namespace(
    compiler: u32,
    namespace_ptr: u32,
    namespace_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let namespace = match string_from_ptr_len(namespace_ptr, namespace_len) {
        Ok(namespace) => namespace,
        Err(code) => {
            return error_result(code, "namespace is not valid UTF-8")
        }
    };

    compiler.inner.new_namespace(&namespace);
    success_result(0)
}

fn define_compiler_global<T>(
    compiler: &mut CompilerState,
    ident: String,
    value: T,
) -> u64
where
    T: TryInto<yara_x::Variable, Error = yara_x::errors::VariableError>,
{
    match compiler.inner.define_global(&ident, value) {
        Ok(_) => success_result(0),
        Err(err) => error_result(YRX_RESULT::YRX_VARIABLE_ERROR, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_define_global_str(
    compiler: u32,
    ident_ptr: u32,
    ident_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    let value = match string_from_ptr_len(value_ptr, value_len) {
        Ok(value) => value,
        Err(code) => return error_result(code, "value is not valid UTF-8"),
    };

    define_compiler_global(compiler, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_define_global_bool(
    compiler: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    define_compiler_global(compiler, ident, value != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_define_global_int(
    compiler: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: i64,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    define_compiler_global(compiler, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_define_global_float(
    compiler: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: f64,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    define_compiler_global(compiler, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_define_global_json(
    compiler: u32,
    ident_ptr: u32,
    ident_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    let value = match json_from_ptr_len(value_ptr, value_len) {
        Ok(value) => value,
        Err(result) => return result,
    };

    define_compiler_global(compiler, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_errors_json(compiler: u32) -> u64 {
    let compiler = match ref_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    serialization_result(compiler.inner.errors())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_warnings_json(compiler: u32) -> u64 {
    let compiler = match ref_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    serialization_result(compiler.inner.warnings())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_build(compiler: u32) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let built =
        mem::replace(&mut compiler.inner, create_compiler(compiler.flags))
            .build();

    success_result(into_handle(RulesState {
        inner: Arc::new(RulesInner { rules: built }),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_compiler_emit_wasm_file(
    compiler: u32,
    path_ptr: u32,
    path_len: u32,
) -> u64 {
    let compiler = match mut_from_handle::<CompilerState>(compiler) {
        Some(compiler) => compiler,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "compiler handle is null",
            )
        }
    };

    let path = match string_from_ptr_len(path_ptr, path_len) {
        Ok(path) => path,
        Err(code) => return error_result(code, "path is not valid UTF-8"),
    };

    let emit_compiler =
        mem::replace(&mut compiler.inner, create_compiler(compiler.flags));

    match emit_compiler.emit_wasm_file(path) {
        Ok(_) => success_result(0),
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_rules_destroy(rules: u32) {
    destroy_handle::<RulesState>(rules);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_rules_count(rules: u32) -> u64 {
    let rules = match ref_from_handle::<RulesState>(rules) {
        Some(rules) => rules,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "rules handle is null",
            )
        }
    };

    success_result(rules.inner.rules.iter().len() as u32)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_rules_serialize(rules: u32) -> u64 {
    let rules = match ref_from_handle::<RulesState>(rules) {
        Some(rules) => rules,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "rules handle is null",
            )
        }
    };

    match rules.inner.rules.serialize() {
        Ok(bytes) => success_result(buffer_from_bytes(bytes) as u32),
        Err(err) => error_result(YRX_RESULT::YRX_SERIALIZATION_ERROR, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_rules_deserialize(
    data_ptr: u32,
    data_len: u32,
) -> u64 {
    let data = match bytes_from_ptr_len(data_ptr, data_len) {
        Ok(data) => data,
        Err(err) => {
            return error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err)
        }
    };

    match yara_x::Rules::deserialize(data) {
        Ok(rules) => success_result(into_handle(RulesState {
            inner: Arc::new(RulesInner { rules }),
        })),
        Err(err) => error_result(YRX_RESULT::YRX_SERIALIZATION_ERROR, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_rules_imports_json(rules: u32) -> u64 {
    let rules = match ref_from_handle::<RulesState>(rules) {
        Some(rules) => rules,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "rules handle is null",
            )
        }
    };

    let imports: Vec<String> =
        rules.inner.rules.imports().map(|import| import.to_string()).collect();

    serialization_result(&imports)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_rules_slice_json(rules: u32) -> u64 {
    let rules = match ref_from_handle::<RulesState>(rules) {
        Some(rules) => rules,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "rules handle is null",
            )
        }
    };

    serialization_result(&rules_to_json(&rules.inner.rules))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_create(
    rules: u32,
    guest_instance_id: u64,
) -> u64 {
    let rules = match ref_from_handle::<RulesState>(rules) {
        Some(rules) => rules,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "rules handle is null",
            )
        }
    };

    if guest_instance_id == 0 {
        return error_result(
            YRX_RESULT::YRX_INVALID_ARGUMENT,
            "guest instance id is zero",
        );
    }

    let rules_arc = Arc::clone(&rules.inner);
    let mut scanner = mem::transmute::<
        yara_x::Scanner<'_>,
        yara_x::Scanner<'static>,
    >(yara_x::Scanner::with_runtime_session(
        &rules_arc.rules,
        guest_instance_id,
    ));
    scanner.console_log(move |message| {
        emit_console_message(guest_instance_id, &message);
    });

    success_result(into_handle(ScannerState {
        _rules: rules_arc,
        inner: Some(scanner),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_destroy(scanner: u32) {
    destroy_handle::<ScannerState>(scanner);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_create(
    rules: u32,
    guest_instance_id: u64,
) -> u64 {
    let rules = match ref_from_handle::<RulesState>(rules) {
        Some(rules) => rules,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "rules handle is null",
            )
        }
    };
    if guest_instance_id == 0 {
        return error_result(
            YRX_RESULT::YRX_INVALID_ARGUMENT,
            "guest instance id is zero",
        );
    }

    let rules_arc = Arc::clone(&rules.inner);
    let mut scanner = mem::transmute::<
        blocks::Scanner<'_>,
        blocks::Scanner<'static>,
    >(blocks::Scanner::with_runtime_session(
        &rules_arc.rules,
        guest_instance_id,
    ));
    scanner.console_log(move |message| {
        emit_console_message(guest_instance_id, &message);
    });

    success_result(into_handle(BlockScannerState {
        _rules: rules_arc,
        inner: Some(scanner),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_destroy(scanner: u32) {
    destroy_handle::<BlockScannerState>(scanner);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_timeout(
    scanner: u32,
    timeout_seconds: u64,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };

    match scanner.inner_mut() {
        Ok(scanner) => {
            scanner
                .set_timeout(std::time::Duration::from_secs(timeout_seconds));
            success_result(0)
        }
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_set_timeout(
    scanner: u32,
    timeout_seconds: u64,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };

    match scanner.inner_mut() {
        Ok(scanner) => {
            scanner
                .set_timeout(std::time::Duration::from_secs(timeout_seconds));
            success_result(0)
        }
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

fn set_scanner_global<T>(
    scanner: &mut ScannerState,
    ident: String,
    value: T,
) -> u64
where
    T: TryInto<yara_x::Variable, Error = yara_x::errors::VariableError>,
{
    match scanner.inner_mut() {
        Ok(scanner) => match scanner.set_global(&ident, value) {
            Ok(_) => success_result(0),
            Err(err) => error_result(YRX_RESULT::YRX_VARIABLE_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

fn set_block_scanner_global<T>(
    scanner: &mut BlockScannerState,
    ident: String,
    value: T,
) -> u64
where
    T: TryInto<yara_x::Variable, Error = yara_x::errors::VariableError>,
{
    match scanner.inner_mut() {
        Ok(scanner) => match scanner.set_global(&ident, value) {
            Ok(_) => success_result(0),
            Err(err) => error_result(YRX_RESULT::YRX_VARIABLE_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_global_str(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    let value = match string_from_ptr_len(value_ptr, value_len) {
        Ok(value) => value,
        Err(code) => return error_result(code, "value is not valid UTF-8"),
    };

    set_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_global_bool(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: u32,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };

    set_scanner_global(scanner, ident, value != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_global_int(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: i64,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };

    set_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_global_float(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: f64,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };

    set_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_global_json(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    let value = match json_from_ptr_len(value_ptr, value_len) {
        Ok(value) => value,
        Err(result) => return result,
    };

    set_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_set_global_str(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    let value = match string_from_ptr_len(value_ptr, value_len) {
        Ok(value) => value,
        Err(code) => return error_result(code, "value is not valid UTF-8"),
    };

    set_block_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_set_global_bool(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: u32,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };

    set_block_scanner_global(scanner, ident, value != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_set_global_int(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: i64,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };

    set_block_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_set_global_float(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value: f64,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };

    set_block_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_set_global_json(
    scanner: u32,
    ident_ptr: u32,
    ident_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };
    let ident = match string_from_ptr_len(ident_ptr, ident_len) {
        Ok(ident) => ident,
        Err(code) => {
            return error_result(code, "identifier is not valid UTF-8")
        }
    };
    let value = match json_from_ptr_len(value_ptr, value_len) {
        Ok(value) => value,
        Err(result) => return result,
    };

    set_block_scanner_global(scanner, ident, value)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_scan(
    scanner: u32,
    base: u64,
    data_ptr: u32,
    data_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };
    let base = match usize_from_u64(base, "base offset") {
        Ok(base) => base,
        Err(result) => return result,
    };
    let data = match bytes_from_ptr_len(data_ptr, data_len) {
        Ok(data) => data,
        Err(err) => {
            return error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err)
        }
    };

    match scanner.inner_mut() {
        Ok(scanner) => match scanner.scan(base, data) {
            Ok(_) => success_result(0),
            Err(yara_x::ScanError::Timeout) => {
                pack_result(YRX_RESULT::YRX_SCAN_TIMEOUT, 0)
            }
            Err(err) => error_result(YRX_RESULT::YRX_SCAN_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_block_scanner_finish(scanner: u32) -> u64 {
    let scanner = match mut_from_handle::<BlockScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "block scanner handle is null",
            )
        }
    };

    match scanner.inner_mut() {
        Ok(scanner) => match scanner.finish() {
            Ok(results) => {
                serialization_result(&matching_rules_to_json(&results))
            }
            Err(yara_x::ScanError::Timeout) => {
                pack_result(YRX_RESULT::YRX_SCAN_TIMEOUT, 0)
            }
            Err(err) => error_result(YRX_RESULT::YRX_SCAN_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_set_module_output(
    scanner: u32,
    name_ptr: u32,
    name_len: u32,
    data_ptr: u32,
    data_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let name = match string_from_ptr_len(name_ptr, name_len) {
        Ok(name) => name,
        Err(code) => {
            return error_result(code, "module name is not valid UTF-8")
        }
    };
    let data = match bytes_from_ptr_len(data_ptr, data_len) {
        Ok(data) => data,
        Err(err) => {
            return error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err)
        }
    };

    match scanner.inner_mut() {
        Ok(scanner) => match scanner.set_module_output_raw(&name, data) {
            Ok(_) => success_result(0),
            Err(err) => error_result(YRX_RESULT::YRX_SCAN_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_scan(
    scanner: u32,
    data_ptr: u32,
    data_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let data = match bytes_from_ptr_len(data_ptr, data_len) {
        Ok(data) => data,
        Err(err) => {
            return error_result(YRX_RESULT::YRX_INVALID_ARGUMENT, err)
        }
    };

    match scanner.inner_mut() {
        Ok(scanner) => match scanner.scan(data) {
            Ok(results) => {
                serialization_result(&matching_rules_to_json(&results))
            }
            Err(yara_x::ScanError::Timeout) => {
                pack_result(YRX_RESULT::YRX_SCAN_TIMEOUT, 0)
            }
            Err(err) => error_result(YRX_RESULT::YRX_SCAN_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_scan_file(
    scanner: u32,
    path_ptr: u32,
    path_len: u32,
) -> u64 {
    let scanner = match mut_from_handle::<ScannerState>(scanner) {
        Some(scanner) => scanner,
        None => {
            return error_result(
                YRX_RESULT::YRX_INVALID_ARGUMENT,
                "scanner handle is null",
            )
        }
    };
    let path = match string_from_ptr_len(path_ptr, path_len) {
        Ok(path) => path,
        Err(code) => return error_result(code, "path is not valid UTF-8"),
    };

    match scanner.inner_mut() {
        Ok(scanner) => match scanner.scan_file(&path) {
            Ok(results) => {
                serialization_result(&matching_rules_to_json(&results))
            }
            Err(yara_x::ScanError::Timeout) => {
                pack_result(YRX_RESULT::YRX_SCAN_TIMEOUT, 0)
            }
            Err(err) => error_result(YRX_RESULT::YRX_SCAN_ERROR, err),
        },
        Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_slowest_rules_json(
    scanner: u32,
    n: u32,
) -> u64 {
    #[cfg(not(feature = "rules-profiling"))]
    {
        let _ = scanner;
        let _ = n;
        return pack_result(YRX_RESULT::YRX_NOT_SUPPORTED, 0);
    }

    #[cfg(feature = "rules-profiling")]
    {
        let scanner = match ref_from_handle::<ScannerState>(scanner) {
            Some(scanner) => scanner,
            None => {
                return error_result(
                    YRX_RESULT::YRX_INVALID_ARGUMENT,
                    "scanner handle is null",
                )
            }
        };

        let profiling: Vec<ProfilingInfoJson> = match scanner.inner_ref() {
            Ok(scanner) => scanner
                .slowest_rules(n as usize)
                .into_iter()
                .map(|item| ProfilingInfoJson {
                    namespace: item.namespace.to_string(),
                    rule: item.rule.to_string(),
                    pattern_matching_time: item
                        .pattern_matching_time
                        .as_secs_f64(),
                    condition_exec_time: item
                        .condition_exec_time
                        .as_secs_f64(),
                })
                .collect(),
            Err(err) => {
                return error_result(YRX_RESULT::YRX_INVALID_STATE, err)
            }
        };

        serialization_result(&profiling)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn go_yrx_scanner_clear_profiling_data(
    scanner: u32,
) -> u64 {
    #[cfg(not(feature = "rules-profiling"))]
    {
        let _ = scanner;
        return pack_result(YRX_RESULT::YRX_NOT_SUPPORTED, 0);
    }

    #[cfg(feature = "rules-profiling")]
    {
        let scanner = match mut_from_handle::<ScannerState>(scanner) {
            Some(scanner) => scanner,
            None => {
                return error_result(
                    YRX_RESULT::YRX_INVALID_ARGUMENT,
                    "scanner handle is null",
                )
            }
        };

        match scanner.inner_mut() {
            Ok(scanner) => {
                scanner.clear_profiling_data();
                success_result(0)
            }
            Err(err) => error_result(YRX_RESULT::YRX_INVALID_STATE, err),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    ptr: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    let safe_align = align.max(1);

    if new_size == 0 {
        if !ptr.is_null() && old_size != 0 {
            let layout =
                Layout::from_size_align_unchecked(old_size, safe_align);
            dealloc(ptr, layout);
        }
        return ptr::null_mut();
    }

    let new_layout = Layout::from_size_align_unchecked(new_size, safe_align);

    if ptr.is_null() || old_size == 0 {
        return alloc(new_layout);
    }

    let old_layout = Layout::from_size_align_unchecked(old_size, safe_align);
    realloc(ptr, old_layout, new_size)
}

fn main() {}
