use std::rc::Rc;

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

#[derive(Default)]
pub struct Dex {
    // DEX header information
    header: DexHeader,

    // List with all found strings
    string_ids: Vec<Rc<String>>,

    // List with all found types
    type_ids: Vec<Rc<String>>,

    // List with all found prototypes
    proto_ids: Vec<Rc<ProtoItem>>,

    // List with all found fields
    field_ids: Vec<FieldItem>,

    // List with all found methods
    method_ids: Vec<MethodItem>,

    // List with all found classes
    class_defs: Vec<ClassItem>,

    // Map information
    map_list: Option<MapList>,
}

impl Dex {
    // the type of endianness used in the file
    const ENDIAN_CONSTANT: u32 = 0x12345678;
    const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

    // lack of information
    const NO_INDEX: u32 = 0xffffffff;

    pub fn parse<'a>(data: &'a [u8]) -> Result<Self, Err<Error<'a>>> {
        // Extract dex header with information about data location
        let (strings_offset, header) = Self::parse_dex_header(data)?;

        // Extract defined strings
        let (types_offset, string_ids) =
            Self::parse_string_ids(strings_offset, data, &header)?;

        // Extract defined types
        let (proto_offset, type_ids) =
            Self::parse_type_ids(types_offset, &header, &string_ids)?;

        // Exctract defined prototypes
        let (field_offset, proto_ids) = Self::parse_proto_ids(
            proto_offset,
            data,
            &header,
            &string_ids,
            &type_ids,
        )?;

        // Extract defined fields
        let (method_offset, field_ids) = Self::parse_field_ids(
            field_offset,
            &header,
            &string_ids,
            &type_ids,
        )?;

        // Extract defined methods
        let (class_offset, method_ids) = Self::parse_method_ids(
            method_offset,
            &header,
            &string_ids,
            &type_ids,
            &proto_ids,
        )?;

        // Exctract defined classes
        let (_, class_defs) = Self::parse_class_defs(
            class_offset,
            &header,
            &string_ids,
            &type_ids,
        )?;

        // Extract map information
        let map_list = Self::parse_map_items(data, &header);

        Ok(Self {
            header,
            string_ids,
            type_ids,
            proto_ids,
            field_ids,
            method_ids,
            class_defs,
            map_list,
        })
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

        // note: nom limits the number of parsers in the tuple to 21, and the header consists of 24 fields
        // note: most verify checks based on android source code (but not strict for catching malware): https://cs.android.com/android/platform/superproject/main/+/main:art/libdexfile/dex/dex_file_verifier.cc;l=618
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
    fn parse_string_ids<'a>(
        remainder: &'a [u8],
        data: &'a [u8],
        header: &DexHeader,
    ) -> IResult<&'a [u8], Vec<Rc<String>>> {
        // DEX file doesn't contain strings.
        // It's a strange case, but it needs to be checked.
        if header.string_ids_off == 0 {
            return Ok((remainder, Vec::new()));
        }

        let mut it = iterator(remainder, le_u32);

        let string_offsets = it
            .by_ref()
            .take(header.string_ids_size as usize)
            .map_while(|offset| Self::parse_string_from_offset(data, offset))
            .map(Rc::new)
            .collect();

        let (rem, _) = it.finish()?;

        Ok((rem, string_offsets))
    }

    /// Parses string by index in the string_ids_off table
    ///
    /// idx - is an index in the string_ids_off table
    /// strings_ids_off[idx] -> string_data_item
    fn parse_string_from_offset(
        data: &[u8],
        string_data_offset: u32,
    ) -> Option<String> {
        data.get(string_data_offset as usize..).and_then(|data| {
            let (data, utf16_size) = uleb128(data).ok()?;
            let (_, bytes) =
                take::<usize, &[u8], Error>(utf16_size as usize)(data).ok()?;

            // Decode MUTF-8 string and save it
            let s = simd_cesu8::mutf8::decode_lossy(bytes).to_string();

            Some(s)
        })
    }

    /// Collects a list of types in a hashmap from type_ids_off list.
    /// Each item in the list is an index that points to a string table.
    ///
    /// `type_item = string_item[type_ids_off[idx]]`
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-id-item
    fn parse_type_ids<'a>(
        remainder: &'a [u8],
        header: &DexHeader,
        string_items: &[Rc<String>],
    ) -> IResult<&'a [u8], Vec<Rc<String>>> {
        // DEX file doesn't contain types.
        // It's a strange case, but it needs to be checked.
        if header.type_ids_off == 0 {
            return Ok((remainder, Vec::new()));
        }

        let mut it = iterator(remainder, le_u32);

        let type_indexes = it
            .by_ref()
            .take(header.type_ids_size as usize)
            .map_while(|idx| string_items.get(idx as usize).cloned())
            .collect();

        let (rem, _) = it.finish()?;

        Ok((rem, type_indexes))
    }

    /// Collects a list of prototypes in a hashmap from proto_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#proto-id-item
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-list
    fn parse_proto_ids<'a>(
        remainder: &'a [u8],
        data: &'a [u8],
        header: &DexHeader,
        string_items: &[Rc<String>],
        type_items: &[Rc<String>],
    ) -> IResult<&'a [u8], Vec<Rc<ProtoItem>>> {
        // DEX file doesn't contain prototypes.
        // It's a strange case, but it needs to be checked.
        if header.proto_ids_off == 0 {
            return Ok((remainder, Vec::new()));
        }

        let mut it = iterator(remainder, (le_u32, le_u32, le_u32));

        let proto_entries = it
            .by_ref()
            .take(header.proto_ids_size as usize)
            .map_while(|(shorty_idx, return_type_idx, parameters_off)| {
                let shorty = string_items.get(shorty_idx as usize)?.clone();
                let return_type =
                    type_items.get(return_type_idx as usize)?.clone();

                // According to the documentation, if parameters_off is 0, then the type has 0 parameters.
                let parameters = if parameters_off == 0 {
                    Vec::new()
                } else {
                    Self::parse_type_list(data, type_items, parameters_off)
                        .unwrap_or_default()
                };

                Some(Rc::new(ProtoItem {
                    shorty,
                    return_type,
                    parameters_count: parameters.len() as u32,
                    parameters,
                }))
            })
            .collect();

        let (rem, _) = it.finish()?;

        Ok((rem, proto_entries))
    }

    /// Collects a type list to list of strings from given offset
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-list
    fn parse_type_list(
        data: &[u8],
        type_items: &[Rc<String>],
        offset: u32,
    ) -> Option<Vec<Rc<String>>> {
        let remainder = data.get(offset as usize..)?;

        let (rem, size) = le_u32::<&[u8], Error>(remainder).ok()?;

        let mut it = iterator(rem, le_u32::<&[u8], Error>);
        let items = it
            .by_ref()
            .take(size as usize)
            .map_while(|idx| type_items.get(idx as usize).cloned())
            .collect();

        let _ = it.finish();

        Some(items)
    }

    /// Collects a list of fields in a hashmap from field_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#field-id-item
    fn parse_field_ids<'a>(
        remainder: &'a [u8],
        header: &DexHeader,
        string_items: &[Rc<String>],
        type_items: &[Rc<String>],
    ) -> IResult<&'a [u8], Vec<FieldItem>> {
        // DEX file doesn't contain fields.
        // It's a strange case, but it needs to be checked.
        if header.field_ids_off == 0 {
            return Ok((remainder, Vec::new()));
        }

        let mut it = iterator(remainder, (le_u16, le_u16, le_u32));

        let field_entries = it
            .by_ref()
            .take(header.field_ids_size as usize)
            .map_while(|(class_idx, type_idx, name_idx)| {
                let class = type_items.get(class_idx as usize)?.clone();
                let type_ = type_items.get(type_idx as usize)?.clone();
                let name = string_items.get(name_idx as usize)?.clone();

                Some(FieldItem { class, type_, name })
            })
            .collect();

        let (rem, _) = it.finish()?;

        Ok((rem, field_entries))
    }

    /// Collects a list of methods in a hashmap from method_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#method-id-item
    fn parse_method_ids<'a>(
        remainder: &'a [u8],
        header: &DexHeader,
        string_items: &[Rc<String>],
        type_items: &[Rc<String>],
        proto_items: &[Rc<ProtoItem>],
    ) -> IResult<&'a [u8], Vec<MethodItem>> {
        // DEX file doesn't contain methods
        // It's a strange case, but it needs to be checked.
        if header.method_ids_off == 0 {
            return Ok((remainder, Vec::new()));
        }

        let mut it = iterator(remainder, (le_u16, le_u16, le_u32));

        let method_entries = it
            .by_ref()
            .take(header.method_ids_size as usize)
            .map_while(|(class_idx, proto_idx, name_idx)| {
                let class = type_items.get(class_idx as usize)?.clone();
                let proto = proto_items.get(proto_idx as usize)?.clone();
                let name = string_items.get(name_idx as usize)?.clone();

                Some(MethodItem { class, proto, name })
            })
            .collect();

        let (rem, _) = it.finish()?;

        Ok((rem, method_entries))
    }

    /// Collects a list of classes from class_defs_off list.
    /// Only a part of the fields is extracted, because not all of them are useful when writing YARA rules.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#class-def-item
    fn parse_class_defs<'a>(
        remainder: &'a [u8],
        header: &DexHeader,
        string_items: &[Rc<String>],
        type_items: &[Rc<String>],
    ) -> IResult<&'a [u8], Vec<ClassItem>> {
        // DEX file doesn't contain classess
        // It's a strange case, but it needs to be checked.
        if header.class_defs_off == 0 {
            return Ok((remainder, Vec::new()));
        }

        // (class_idx, access_flags, superclass_idx, _, source_file_idx)
        let mut it =
            iterator(remainder, (le_u32, le_u32, le_u32, le_u32, le_u32));

        let class_entries = it
            .by_ref()
            .take(header.class_defs_size as usize)
            .map_while(
                |(
                    class_idx,
                    access_flags,
                    superclass_idx,
                    _,
                    source_file_idx,
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

                    Some(ClassItem {
                        class,
                        access_flags,
                        superclass,
                        source_file,
                    })
                },
            )
            .collect();

        let (rem, _) = it.finish()?;

        Ok((rem, class_entries))
    }

    /// Collects information about maps from the DEX file
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#map-list
    fn parse_map_items(data: &[u8], header: &DexHeader) -> Option<MapList> {
        data.get(header.map_off as usize..).and_then(|offset| {
            let (items_offset, size) = le_u32::<&[u8], Error>(offset).ok()?;

            let mut it = iterator(items_offset, Self::parse_map_item);
            let items = it.by_ref().take(size as usize).collect();
            let _ = it.finish();

            Some(MapList { size, items })
        })
    }

    /// Parse single map_item from given input
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#map-item
    #[inline]
    fn parse_map_item(input: &[u8]) -> IResult<&[u8], MapItem> {
        let (remainder, (item_type, unused, size, offset)) = (
            le_u16, // type
            le_u16, // unused
            le_u32, // size
            le_u32, // offset
        )
            .parse(input)?;

        Ok((remainder, MapItem { item_type, unused, size, offset }))
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

#[derive(Debug)]
pub struct ProtoItem {
    shorty: Rc<String>,
    return_type: Rc<String>,
    parameters_count: u32,
    parameters: Vec<Rc<String>>,
}

#[derive(Debug)]
pub struct FieldItem {
    class: Rc<String>,
    type_: Rc<String>,
    name: Rc<String>,
}

#[derive(Debug)]
pub struct MethodItem {
    class: Rc<String>,
    proto: Rc<ProtoItem>,
    name: Rc<String>,
}

#[derive(Debug)]
pub struct ClassItem {
    class: Rc<String>,
    access_flags: u32,
    superclass: Option<Rc<String>>,
    source_file: Option<Rc<String>>,
}

#[derive(Default)]
pub struct MapList {
    size: u32,
    items: Vec<MapItem>,
}

#[derive(Default)]
pub struct MapItem {
    item_type: u16,
    unused: u16,
    size: u32,
    offset: u32,
}

impl From<Dex> for protos::dex::Dex {
    fn from(dex: Dex) -> Self {
        let mut result = protos::dex::Dex::new();

        result.set_is_dex(true);
        result.header = MessageField::some(dex.header.clone().into());

        result
            .string_ids
            .extend(dex.string_ids.into_iter().map(|x| x.as_ref().clone()));
        result
            .type_ids
            .extend(dex.type_ids.into_iter().map(|x| x.as_ref().clone()));
        result.proto_ids.extend(
            dex.proto_ids
                .iter()
                .map(|x| protos::dex::ProtoItem::from(x.as_ref())),
        );
        result
            .field_ids
            .extend(dex.field_ids.iter().map(protos::dex::FieldItem::from));
        result
            .method_ids
            .extend(dex.method_ids.iter().map(protos::dex::MethodItem::from));
        result
            .class_defs
            .extend(dex.class_defs.iter().map(protos::dex::ClassItem::from));

        if let Some(map_list) = dex.map_list {
            result.map_list = MessageField::some(map_list.into());
        }

        result
    }
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
        result.set_map_off(header.map_off);
        result.set_string_ids_size(header.string_ids_size);
        result.set_string_ids_off(header.string_ids_off);
        result.set_type_ids_size(header.type_ids_size);
        result.set_type_ids_off(header.type_ids_off);
        result.set_proto_ids_size(header.proto_ids_size);
        result.set_proto_ids_off(header.proto_ids_off);
        result.set_field_ids_size(header.field_ids_size);
        result.set_field_ids_off(header.field_ids_off);
        result.set_method_ids_size(header.method_ids_size);
        result.set_method_ids_off(header.method_ids_off);
        result.set_class_defs_size(header.class_defs_size);
        result.set_class_defs_off(header.class_defs_off);
        result.set_data_size(header.data_size);
        result.set_data_off(header.data_off);
        result.container_size = header.container_size;
        result.header_offset = header.header_offset;
        result
    }
}

impl From<&ProtoItem> for protos::dex::ProtoItem {
    fn from(value: &ProtoItem) -> Self {
        let mut result = protos::dex::ProtoItem::new();

        result.shorty = Some(value.shorty.to_string());
        result.return_type = Some(value.return_type.to_string());
        result.set_parameters_count(value.parameters_count);
        result
            .parameters
            .extend(value.parameters.iter().map(|x| x.as_ref().into()));

        result
    }
}

impl From<&FieldItem> for protos::dex::FieldItem {
    fn from(value: &FieldItem) -> Self {
        let mut result = protos::dex::FieldItem::new();

        result.class = Some(value.class.to_string());
        result.type_ = Some(value.type_.to_string());
        result.name = Some(value.name.to_string());

        result
    }
}

impl From<&MethodItem> for protos::dex::MethodItem {
    fn from(value: &MethodItem) -> Self {
        let mut result = protos::dex::MethodItem::new();

        result.class = Some(value.class.to_string());
        result.proto = MessageField::some(value.proto.as_ref().into());
        result.name = Some(value.name.to_string());

        result
    }
}

impl From<&ClassItem> for protos::dex::ClassItem {
    fn from(value: &ClassItem) -> Self {
        let mut result = protos::dex::ClassItem::new();

        result.class = Some(value.class.to_string());
        result.set_access_flags(value.access_flags);

        if let Some(superclass) = &value.superclass {
            result.superclass = Some(superclass.to_string());
        }

        if let Some(source_file) = &value.source_file {
            result.source_file = Some(source_file.to_string());
        }

        result
    }
}

impl From<MapList> for protos::dex::MapList {
    fn from(value: MapList) -> Self {
        let mut result = protos::dex::MapList::new();

        result.set_size(value.size);
        result.items =
            value.items.iter().map(protos::dex::MapItem::from).collect();

        result
    }
}

impl From<&MapItem> for protos::dex::MapItem {
    fn from(item: &MapItem) -> Self {
        let mut result = protos::dex::MapItem::new();

        result.type_ = Some(EnumOrUnknown::from_i32(item.item_type.into()));
        result.set_unused(item.unused.into());
        result.set_size(item.size);
        result.set_offset(item.offset);

        result
    }
}
