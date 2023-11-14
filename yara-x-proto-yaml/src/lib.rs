use itertools::Itertools;
use protobuf::MessageDyn;
use std::cmp::Ordering;
use std::io::{Error, Write};

use protobuf::reflect::ReflectFieldRef::{Map, Optional, Repeated};
use protobuf::reflect::ReflectValueRef;
use protobuf::reflect::{FieldDescriptor, MessageRef};

#[cfg(test)]
mod tests;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

/// Serializes a protobuf to YAML format.
///
/// Takes a protobuf message and produces a YAML representation of it. The
/// produced YAML intends to be as human-friendly as possible, by including
/// comments that clarify the meaning of certain values, like timestamps.
pub struct Serializer<W: Write> {
    indent: u16,
    output: W,
}

impl<W: Write> Serializer<W> {
    /// Creates a new YAML serializer that writes its output to `w`.
    pub fn new(w: W) -> Self {
        Self { output: w, indent: 0 }
    }

    /// Serializes the given protobuf message.
    pub fn serialize(&mut self, msg: &dyn MessageDyn) -> Result<(), Error> {
        self.write_msg(&MessageRef::new(msg))
    }
}

impl<W: Write> Serializer<W> {
    fn write_field_name(&mut self, name: &str) -> Result<(), Error> {
        write!(self.output, "{}:", name)
    }

    fn write_msg(&mut self, msg: &MessageRef) -> Result<(), Error> {
        let descriptor = msg.descriptor_dyn();

        // Iterator that returns only the non-empty fields in the message.
        let mut non_empty_fields = descriptor
            .fields()
            .filter(|field| match field.get_reflect(&**msg) {
                Optional(optional) => optional.value().is_some(),
                Repeated(repeated) => !repeated.is_empty(),
                Map(map) => !map.is_empty(),
            })
            .peekable();

        while let Some(field) = non_empty_fields.next() {
            match field.get_reflect(&**msg) {
                Optional(optional) => {
                    let value = optional.value().unwrap();
                    self.write_field_name(field.name())?;
                    self.indent += 2;
                    self.write_name_value_separator(&value)?;
                    self.write_value(&field, &value)?;
                    self.indent -= 2;
                }
                Repeated(repeated) => {
                    self.write_field_name(field.name())?;
                    self.newline()?;
                    let mut items = repeated.into_iter().peekable();
                    while let Some(value) = items.next() {
                        write!(self.output, "- ")?;
                        self.indent += 2;
                        self.write_value(&field, &value)?;
                        self.indent -= 2;
                        if items.peek().is_some() {
                            self.newline()?;
                        }
                    }
                }
                Map(map) => {
                    self.write_field_name(field.name())?;
                    self.indent += 2;
                    self.newline()?;

                    // Iteration order is not stable (i.e: the order in which
                    // items are returned can vary from one execution to the
                    // other), because the underlying data structure is a
                    // HashMap. For this reason items are wrapped in a KV
                    // struct (which implement the Ord trait) and sorted.
                    // Key-value pairs are sorted by key.
                    let mut items = map
                        .into_iter()
                        .map(|(key, value)| KV { key, value })
                        .sorted()
                        .peekable();

                    while let Some(item) = items.next() {
                        self.write_field_name(item.key.to_string().as_str())?;
                        self.indent += 2;
                        self.write_name_value_separator(&item.value)?;
                        self.write_value(&field, &item.value)?;
                        self.indent -= 2;
                        if items.peek().is_some() {
                            self.newline()?;
                        }
                    }
                    self.indent -= 2;
                }
            }

            if non_empty_fields.peek().is_some() {
                self.newline()?;
            }
        }

        Ok(())
    }

    fn write_value(
        &mut self,
        field_descriptor: &FieldDescriptor,
        value: &ReflectValueRef,
    ) -> Result<(), Error> {
        match value {
            ReflectValueRef::U32(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::U64(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::I32(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::I64(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::F32(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::F64(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::Bool(v) => write!(self.output, "{}", v)?,
            ReflectValueRef::String(v) => write!(self.output, "{:?}", v)?,
            ReflectValueRef::Bytes(_) => {
                todo!()
            }
            ReflectValueRef::Enum(_, _) => {
                todo!()
            }
            ReflectValueRef::Message(msg) => self.write_msg(msg)?,
        }
        Ok(())
    }

    fn newline(&mut self) -> Result<(), Error> {
        writeln!(self.output)?;
        for _ in 0..self.indent {
            write!(self.output, " ")?;
        }
        Ok(())
    }

    fn write_name_value_separator(
        &mut self,
        value: &ReflectValueRef,
    ) -> Result<(), Error> {
        if let ReflectValueRef::Message(_) = value {
            self.newline()?
        } else {
            write!(self.output, " ")?
        }
        Ok(())
    }
}

/// Helper type that allows to sort the entries in protobuf map.
struct KV<'a> {
    key: ReflectValueRef<'a>,
    value: ReflectValueRef<'a>,
}

impl PartialOrd for KV<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KV<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.key {
            ReflectValueRef::U32(v) => {
                v.cmp(&other.key.to_u32().unwrap_or_default())
            }
            ReflectValueRef::U64(v) => {
                v.cmp(&other.key.to_u64().unwrap_or_default())
            }
            ReflectValueRef::I32(v) => {
                v.cmp(&other.key.to_i32().unwrap_or_default())
            }
            ReflectValueRef::I64(v) => {
                v.cmp(&other.key.to_i64().unwrap_or_default())
            }
            ReflectValueRef::Bool(v) => {
                v.cmp(&other.key.to_bool().unwrap_or_default())
            }
            ReflectValueRef::String(v) => {
                v.cmp(other.key.to_str().unwrap_or_default())
            }
            _ => {
                // Protobuf doesn't support map keys of any other type
                // except the ones listed above.
                panic!("unsupported type in map key")
            }
        }
    }
}

impl PartialEq for KV<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.key.to_str().eq(&other.key.to_str())
    }
}

impl Eq for KV<'_> {}
