use crate::YRX_BUFFER;
use std::ffi::{c_char, CString};
use std::ptr::slice_from_raw_parts_mut;

/// Represents the metadata associated to a rule.
#[repr(C)]
pub struct YRX_METADATA {
    /// Number of metadata entries.
    pub num_entries: usize,
    /// Pointer to an array of YRX_METADATA_ENTRY structures. The array has
    /// num_entries items. If num_entries is zero this pointer is invalid
    /// and should not be de-referenced.
    pub entries: *mut YRX_METADATA_ENTRY,
}

impl Drop for YRX_METADATA {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(slice_from_raw_parts_mut(
                self.entries,
                self.num_entries,
            )));
        }
    }
}

/// Metadata value types.
#[repr(C)]
#[allow(missing_docs)]
pub enum YRX_METADATA_VALUE_TYPE {
    I64,
    F64,
    BOOLEAN,
    STRING,
    BYTES,
}

/// Represents a metadata value that contains raw bytes.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct YRX_METADATA_BYTES {
    /// Number of bytes.
    pub length: usize,
    /// Pointer to the bytes.
    pub data: *mut u8,
}

/// Metadata value.
#[repr(C)]
pub union YRX_METADATA_VALUE {
    /// Value if the metadata is I64.
    pub r#i64: i64,
    /// Value if the metadata is F64.
    pub r#f64: f64,
    /// Value if the metadata is BOOLEAN.
    pub boolean: bool,
    /// Value if the metadata is STRING.
    pub string: *mut c_char,
    /// Value if the metadata is BYTES.
    pub bytes: YRX_METADATA_BYTES,
}

/// A metadata entry.
#[repr(C)]
pub struct YRX_METADATA_ENTRY {
    /// Metadata identifier.
    pub identifier: *mut c_char,
    /// Type of value.
    pub value_type: YRX_METADATA_VALUE_TYPE,
    /// The value itself. This is a union, use the member that matches the
    /// value type.
    pub value: YRX_METADATA_VALUE,
}

impl Drop for YRX_METADATA_ENTRY {
    fn drop(&mut self) {
        unsafe {
            drop(CString::from_raw(self.identifier));
            match self.value_type {
                YRX_METADATA_VALUE_TYPE::STRING => {
                    drop(CString::from_raw(self.value.string));
                }
                YRX_METADATA_VALUE_TYPE::BYTES => {
                    drop(Box::from_raw(slice_from_raw_parts_mut(
                        self.value.bytes.data,
                        self.value.bytes.length,
                    )));
                }
                _ => {}
            }
        }
    }
}

/// Destroys a [`YRX_METADATA`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_metadata_destroy(metadata: *mut YRX_METADATA) {
    drop(Box::from_raw(metadata));
}

/// Destroys a [`YRX_BUFFER`] object.
#[no_mangle]
pub unsafe extern "C" fn yrx_buffer_destroy(buf: *mut YRX_BUFFER) {
    drop(Box::from_raw(buf));
}
