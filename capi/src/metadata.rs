use std::ffi::c_char;

/// Types of metadata values.
#[repr(C)]
#[allow(missing_docs)]
pub enum YRX_METADATA_TYPE {
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
    pub data: *const u8,
}

/// A metadata value.
#[repr(C)]
pub union YRX_METADATA_VALUE {
    /// Value if the metadata is I64.
    pub r#i64: i64,
    /// Value if the metadata is F64.
    pub r#f64: f64,
    /// Value if the metadata is BOOLEAN.
    pub boolean: bool,
    /// Value if the metadata is STRING.
    pub string: *const c_char,
    /// Value if the metadata is BYTES.
    pub bytes: YRX_METADATA_BYTES,
}

/// A metadata entry.
#[repr(C)]
pub struct YRX_METADATA {
    /// Metadata identifier.
    pub identifier: *const c_char,
    /// Metadata type.
    pub value_type: YRX_METADATA_TYPE,
    /// Metadata value.
    ///
    /// This a union type, the variant that should be used is determined by the
    /// type indicated in `value_type`.
    pub value: YRX_METADATA_VALUE,
}
