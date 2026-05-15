use nom::bytes::complete::take;
use nom::combinator::iterator;
use nom::combinator::{cond, map, map_res, verify};
use nom::error::ErrorKind;
use nom::number::complete::{be_u16, be_u32, le_u16, le_u32, u8};
use nom::{Err, IResult, Parser};
use protobuf::{EnumOrUnknown, MessageField};

use crate::modules::protos;
use crate::modules::utils::leb128::uleb128;

type Error<'a> = nom::error::Error<&'a [u8]>;

pub struct Dex;

impl Dex {
    const ENDIAN_CONSTANT: u32 = 0x12345678;
    const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;
    const DEX_HEADER_SIZE: u32 = 0x70;
    const NO_INDEX: u32 = 0xffffffff;

    const MAX_STRINGS: usize = 1_000_000;
    const MAX_TYPES: usize = 1_000_000;
    const MAX_PROTOS: usize = 1_000_000;
    const MAX_CLASSES: usize = 1_000_000;
    const MAX_METHODS: usize = 1_000_000;
    const MAX_FIELDS: usize = 1_000_000;

    pub fn parse(data: &[u8]) -> Result<protos::dex::Dex, Err<Error<'_>>> {
        // Extract dex header with information about data location
        let (_, header) = Self::parse_dex_header(data)?;

        // Extract defined strings
        let strings = Self::parse_strings(data, &header);

        // Extract defined types
        let types = Self::parse_types(data, &header, &strings);

        // Extract defined prototypes
        let protos = Self::parse_protos(data, &header, &strings, &types);

        // Extract defined fields
        let fields = Self::parse_fields(data, &header, &strings, &types);

        // Extract defined methods
        let methods =
            Self::parse_methods(data, &header, &strings, &types, &protos);

        // Extract defined classes
        let class_defs =
            Self::parse_class_defs(data, &header, &strings, &types);

        // Extract map information
        let map_list = Self::parse_map_items(data, &header);

        let mut dex = protos::dex::Dex::new();
        dex.set_is_dex(true);

        dex.header = MessageField::some(header.into());
        dex.strings = strings;
        dex.types = types;
        dex.protos = protos;
        dex.fields = fields;
        dex.methods = methods;
        dex.class_defs = class_defs;

        if let Some(map_list) = map_list {
            dex.map_list = MessageField::some(map_list);
        }

        Ok(dex)
    }

    fn parse_dex_header(data: &[u8]) -> IResult<&[u8], DexHeader> {
        let (mut remainder, (magic, _, version, _)) = (
            // magic must be 'dex\n'
            verify(be_u32, |magic| *magic == 0x6465780A),
            // part of dex version, must be 0x30
            verify(u8, |b| *b == 0x30),
            // extract dex version
            map_res(be_u16, DexVersion::try_from),
            // part of dex version, must be 0x00
            verify(u8, |b| *b == 0x00),
        )
            .parse(data)?;

        let mut header = DexHeader { magic, version, ..DexHeader::default() };

        let file_size = data.len() as u32;

        // note: nom limits the number of parsers in the tuple to 21, and the
        // header consists of 24 fields
        // note: most verify checks based on android source code (but not
        // strict for catching malware):
        // https://cs.android.com/android/platform/superproject/main/+/main:art/libdexfile/dex/dex_file_verifier.cc;l=618
        (
            remainder,
            (
                header.checksum,
                header.signature,
                header.file_size,
                header.header_size,
                header.endian_tag,
                header.link_size,
                header.link_off,
                header.map_off,
                header.string_ids_size,
                header.string_ids_off,
                header.type_ids_size,
                header.type_ids_off,
            ),
        ) = (
            le_u32, // checksum
            map(take(20_u8), |v: &[u8]| {
                v.iter().map(|b| format!("{b:02x}")).collect()
            }), // signature
            verify(le_u32, |&size| size <= file_size), // file_size
            // There should be a check for header size depending on the DEX version,
            // but the format itself does not follow this.
            verify(le_u32, |&size| size == 0x70), // header_size
            verify(le_u32, |&tag| {
                tag == Self::ENDIAN_CONSTANT
                    || tag == Self::REVERSE_ENDIAN_CONSTANT
            }), // endian_tag
            le_u32,                               // link_size
            verify(le_u32, |&offset| offset <= file_size), // link_off
            verify(le_u32, |&offset| offset <= file_size), // map_off
            le_u32,                               // string_ids_size
            verify(le_u32, |&offset| offset <= file_size), // string_ids_off
            verify(le_u32, |&size| size <= u16::MAX.into()), // type_ids_size
            verify(le_u32, |&offset| offset <= file_size), // type_ids_off
        )
            .parse(remainder)?;

        (
            remainder,
            (
                header.proto_ids_size,
                header.proto_ids_off,
                header.field_ids_size,
                header.field_ids_off,
                header.method_ids_size,
                header.method_ids_off,
                header.class_defs_size,
                header.class_defs_off,
                header.data_size,
                header.data_off,
                header.container_size,
                header.header_offset,
            ),
        ) = (
            verify(le_u32, |&size| size <= u16::MAX.into()), // proto_ids_size
            verify(le_u32, |&offset| offset <= file_size),   // proto_ids_off
            le_u32,                                          // field_ids_size
            verify(le_u32, |&offset| offset <= file_size),   // field_ids_off
            le_u32,                                          // method_ids_size
            verify(le_u32, |&offset| offset <= file_size),   // method_ids_off
            le_u32,                                          // class_defs_size
            verify(le_u32, |&offset| offset <= file_size),   // class_defs_off
            le_u32,                                          // data_size
            verify(le_u32, |&offset| offset <= file_size),   // data_off
            cond(header.version >= DexVersion::DEX41, le_u32), // container_size
            cond(header.version >= DexVersion::DEX41, le_u32), // header_offset
        )
            .parse(remainder)?;

        Ok((remainder, header))
    }

    /// Collects a list of strings in a hashmap from string_ids_off list.
    /// A HashMap is needed to quickly access an item by its index.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#string-item
    fn parse_strings(data: &[u8], header: &DexHeader) -> Vec<String> {
        // DEX file doesn't contain strings.
        // It's a strange case, but it needs to be checked.
        if header.string_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.string_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        iterator(table_slice, le_u32::<&[u8], Error>)
            .take(Self::MAX_STRINGS)
            .take(header.string_ids_size as usize)
            .filter_map(|offset| Self::parse_string_from_offset(data, offset))
            .collect()
    }

    /// Parses string by index in the string_ids_off table
    ///
    /// idx - is an index in the string_ids_off table
    /// strings_ids_off[idx] -> string_data_item
    ///
    /// Strings larger than 64KB will be considered invalid and the result will
    /// be None.
    fn parse_string_from_offset(
        data: &[u8],
        string_data_offset: u32,
    ) -> Option<String> {
        if string_data_offset < Self::DEX_HEADER_SIZE {
            return None;
        }

        data.get(string_data_offset as usize..).and_then(|slice| {
            let (slice, utf16_size) = uleb128(slice).ok()?;

            if utf16_size > 65536 || (utf16_size as usize) > data.len() {
                return None;
            }

            let (_, bytes) =
                take::<usize, &[u8], Error>(utf16_size as usize)(slice)
                    .ok()?;

            // Decode MUTF-8 string and return String
            simd_cesu8::mutf8::decode(bytes).ok().map(|s| s.into_owned())
        })
    }

    /// Collects a list of types in a hashmap from type_ids_off list.
    /// Each item in the list is an index that points to a string table.
    ///
    /// `type_item = string_item[type_ids_off[idx]]`
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-id-item
    fn parse_types(
        data: &[u8],
        header: &DexHeader,
        string_items: &[String],
    ) -> Vec<String> {
        // DEX file doesn't contain types.
        // It's a strange case, but it needs to be checked.
        if header.type_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.type_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        iterator(table_slice, le_u32::<&[u8], Error>)
            .take(Self::MAX_TYPES)
            .take(header.type_ids_size as usize)
            .filter_map(|idx| string_items.get(idx as usize).cloned())
            .collect()
    }

    /// Collects a list of prototypes in a hashmap from proto_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#proto-id-item
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-list
    fn parse_protos(
        data: &[u8],
        header: &DexHeader,
        string_items: &[String],
        type_items: &[String],
    ) -> Vec<protos::dex::ProtoItem> {
        // DEX file doesn't contain prototypes.
        // It's a strange case, but it needs to be checked.
        if header.proto_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.proto_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        iterator(table_slice, (le_u32::<&[u8], Error>, le_u32, le_u32))
            .take(Self::MAX_PROTOS)
            .take(header.proto_ids_size as usize)
            .filter_map(|(shorty_idx, return_type_idx, parameters_off)| {
                let shorty = string_items.get(shorty_idx as usize)?.clone();
                let return_type =
                    type_items.get(return_type_idx as usize)?.clone();

                // According to the documentation, if parameters_off is 0, then
                // the type has 0 parameters.
                let parameters = if parameters_off == 0 {
                    Vec::new()
                } else {
                    Self::parse_type_list(data, type_items, parameters_off)
                        .unwrap_or_default()
                };

                let mut item = protos::dex::ProtoItem::new();
                item.shorty = Some(shorty);
                item.return_type = Some(return_type);
                item.set_parameters_count(parameters.len() as u32);
                item.parameters.extend(parameters);
                Some(item)
            })
            .collect()
    }

    /// Collects a type list to list of strings from given offset
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-list
    fn parse_type_list(
        data: &[u8],
        type_items: &[String],
        offset: u32,
    ) -> Option<Vec<String>> {
        let remainder = data.get(offset as usize..)?;
        let (remainder, size) = le_u32::<&[u8], Error>(remainder).ok()?;

        // The number of arguments can't be higher than 255 due to constraints
        // in the Dalvik bytecode instruction set itself.
        if size > 255 {
            return None;
        }

        Some(
            iterator(remainder, le_u16::<&[u8], Error>)
                .take(size as usize)
                .filter_map(|idx| type_items.get(idx as usize).cloned())
                .collect(),
        )
    }

    /// Collects a list of fields in a hashmap from field_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#field-id-item
    fn parse_fields(
        data: &[u8],
        header: &DexHeader,
        string_items: &[String],
        type_items: &[String],
    ) -> Vec<protos::dex::FieldItem> {
        // DEX file doesn't contain fields.
        // It's a strange case, but it needs to be checked.
        if header.field_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.field_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        iterator(table_slice, (le_u16::<&[u8], Error>, le_u16, le_u32))
            .take(Self::MAX_FIELDS)
            .take(header.field_ids_size as usize)
            .filter_map(|(class_idx, type_idx, name_idx)| {
                let class = type_items.get(class_idx as usize)?.clone();
                let type_ = type_items.get(type_idx as usize)?.clone();
                let name = string_items.get(name_idx as usize)?.clone();
                let mut item = protos::dex::FieldItem::new();
                item.class = Some(class);
                item.type_ = Some(type_);
                item.name = Some(name);
                Some(item)
            })
            .collect()
    }

    /// Collects a list of methods in a hashmap from method_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#method-id-item
    fn parse_methods(
        data: &[u8],
        header: &DexHeader,
        string_items: &[String],
        type_items: &[String],
        proto_items: &[protos::dex::ProtoItem],
    ) -> Vec<protos::dex::MethodItem> {
        // DEX file doesn't contain methods
        // It's a strange case, but it needs to be checked.
        if header.method_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.method_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        iterator(table_slice, (le_u16::<&[u8], Error>, le_u16, le_u32))
            .take(Self::MAX_METHODS)
            .take(header.method_ids_size as usize)
            .filter_map(|(class_idx, proto_idx, name_idx)| {
                let class = type_items.get(class_idx as usize)?.clone();
                let proto = proto_items.get(proto_idx as usize)?.clone();
                let name = string_items.get(name_idx as usize)?.clone();

                let mut item = protos::dex::MethodItem::new();
                item.class = Some(class);
                item.proto = MessageField::some(proto);
                item.name = Some(name);
                Some(item)
            })
            .collect()
    }

    /// Collects a list of classes from class_defs_off list.
    /// Only a part of the fields is extracted, because not all of them are
    /// useful when writing YARA rules.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#class-def-item
    fn parse_class_defs(
        data: &[u8],
        header: &DexHeader,
        string_items: &[String],
        type_items: &[String],
    ) -> Vec<protos::dex::ClassItem> {
        // DEX file doesn't contain classess
        // It's a strange case, but it needs to be checked.
        if header.class_defs_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.class_defs_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        let it = iterator(
            table_slice,
            (
                le_u32::<&[u8], Error>, // class_idx
                le_u32,                 // access_flags
                le_u32,                 // superclass_idx
                le_u32,                 // interfaces_off
                le_u32,                 // source_file_idx
                le_u32,                 // annotations_off
                le_u32,                 // class_data_off
                le_u32,                 // static_values_off
            ),
        );

        it.take(Self::MAX_CLASSES)
            .take(header.class_defs_size as usize)
            .filter_map(
                |(
                    class_idx,
                    access_flags,
                    superclass_idx,
                    _,
                    source_file_idx,
                    _,
                    _,
                    _,
                )| {
                    let class = type_items.get(class_idx as usize)?.clone();
                    let superclass = if superclass_idx != Self::NO_INDEX {
                        type_items.get(superclass_idx as usize).cloned()
                    } else {
                        None
                    };
                    let source_file = if source_file_idx != Self::NO_INDEX {
                        string_items.get(source_file_idx as usize).cloned()
                    } else {
                        None
                    };

                    let mut item = protos::dex::ClassItem::new();
                    item.class = Some(class);
                    item.set_access_flags(access_flags);
                    if let Some(superclass) = superclass {
                        item.superclass = Some(superclass);
                    }
                    if let Some(source_file) = source_file {
                        item.source_file = Some(source_file);
                    }
                    Some(item)
                },
            )
            .collect()
    }

    /// Collects information about maps from the DEX file
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#map-list
    fn parse_map_items(
        data: &[u8],
        header: &DexHeader,
    ) -> Option<protos::dex::MapList> {
        data.get(header.map_off as usize..).and_then(|offset| {
            let (items_offset, size) = le_u32::<&[u8], Error>(offset).ok()?;
            let items: Vec<protos::dex::MapItem> =
                iterator(items_offset, Self::parse_map_item)
                    .take(size as usize)
                    .collect();

            let mut map_list = protos::dex::MapList::new();

            map_list.set_size(size);
            map_list.items = items;

            Some(map_list)
        })
    }

    /// Parse single map_item from given input
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#map-item
    #[inline]
    fn parse_map_item(input: &[u8]) -> IResult<&[u8], protos::dex::MapItem> {
        let (remainder, (item_type, unused, size, offset)) = (
            le_u16, // type
            le_u16, // unused
            le_u32, // size
            le_u32, // offset
        )
            .parse(input)?;

        let mut item = protos::dex::MapItem::new();
        item.type_ = Some(EnumOrUnknown::from_i32(item_type.into()));
        item.set_unused(unused.into());
        item.set_size(size);
        item.set_offset(offset);

        Ok((remainder, item))
    }
}

#[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
enum DexVersion {
    #[default]
    DEX35,
    DEX36,
    DEX37,
    DEX38,
    DEX39,
    DEX40,
    DEX41,
}

impl TryFrom<u16> for DexVersion {
    type Error = Error<'static>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x3335 => Ok(DexVersion::DEX35),
            0x3336 => Ok(DexVersion::DEX36),
            0x3337 => Ok(DexVersion::DEX37),
            0x3338 => Ok(DexVersion::DEX38),
            0x3339 => Ok(DexVersion::DEX39),
            0x3430 => Ok(DexVersion::DEX40),
            0x3431 => Ok(DexVersion::DEX41),
            _ => Err(Error::new(&[], ErrorKind::Verify)),
        }
    }
}

impl From<DexVersion> for u32 {
    fn from(value: DexVersion) -> Self {
        match value {
            DexVersion::DEX35 => 35,
            DexVersion::DEX36 => 36,
            DexVersion::DEX37 => 37,
            DexVersion::DEX38 => 38,
            DexVersion::DEX39 => 39,
            DexVersion::DEX40 => 40,
            DexVersion::DEX41 => 41,
        }
    }
}

#[derive(Default, Debug, Clone)]
struct DexHeader {
    magic: u32,
    version: DexVersion,
    checksum: u32,
    signature: String,
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32,
    container_size: Option<u32>,
    header_offset: Option<u32>,
}

impl From<DexHeader> for protos::dex::DexHeader {
    fn from(header: DexHeader) -> Self {
        let mut result = protos::dex::DexHeader::new();

        result.set_magic(header.magic);
        result.set_version(header.version.into());
        result.set_checksum(header.checksum);
        result.set_signature(header.signature);
        result.set_file_size(header.file_size);
        result.set_header_size(header.header_size);
        result.set_endian_tag(header.endian_tag);
        result.set_link_size(header.link_size);
        result.set_link_off(header.link_off);
        result.container_size = header.container_size;
        result.header_offset = header.header_offset;
        result
    }
}
