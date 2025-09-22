use crate::modules::protos;
use nom::bytes::complete::take;
use nom::combinator::{cond, map, map_res, verify};
use nom::error::ErrorKind;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, le_u16, le_u32, u8};
use nom::{Err, IResult, Parser};
use protobuf::{EnumOrUnknown, MessageField};
use std::cell::OnceCell;
use std::collections::HashMap;
use std::rc::Rc;

type Error<'a> = nom::error::Error<&'a [u8]>;

const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;
// const NO_INDEX: u32 = 0xffffffff;

#[derive(Default)]
pub struct Dex<'a> {
    data: &'a [u8],
    header: DexHeader,
    string_items: OnceCell<HashMap<u32, Rc<StringItem>>>,
    type_items: OnceCell<HashMap<u32, Rc<StringItem>>>,
    proto_items: OnceCell<HashMap<u32, Rc<ProtoItem>>>,
    field_items: OnceCell<HashMap<u32, Rc<FieldItem>>>,
    method_items: OnceCell<HashMap<u32, Rc<MethodItem>>>,
    class_items: OnceCell<Vec<Rc<ClassItem>>>,
    map_items: OnceCell<MapList>,
}

impl<'a> Dex<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Err<Error<'a>>> {
        // Extract dex header with information about data location
        let (_, header) = Self::parse_dex_header(data)?;

        Ok(Self { data, header, ..Dex::default() })
    }

    fn parse_dex_header(data: &[u8]) -> IResult<&[u8], DexHeader> {
        let (mut remainder, (magic, _, version, _)) = (
            verify(be_u32, |magic| *magic == 0x6465780A), // magic must be 'dex\n'
            verify(u8, |b| *b == 0x30),                   // expect 0x30
            map_res(be_u16, DexVersion::try_from),        // dex version
            verify(u8, |b| *b == 0x00),                   // expect 0x00
        )
            .parse(data)?;

        let mut header = DexHeader::default();
        header.magic = magic;
        header.version = version;

        // note: nom limits the number of parsers in the tuple to 21, and the header consists of 24 fields
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
                v.iter().map(|b| format!("{:02x}", b)).collect()
            }), // signature
            le_u32, // file_size
            // There should be a check for header size depending on the DEX version,
            // but the format itself does not follow this.
            verify(le_u32, |file_size| *file_size == 0x70), // header_size
            verify(le_u32, |tag| {
                *tag == ENDIAN_CONSTANT || *tag == REVERSE_ENDIAN_CONSTANT
            }), // endian_tag
            le_u32,                                         // link_size
            le_u32,                                         // link_off
            le_u32,                                         // map_off
            le_u32,                                         // string_ids_size
            le_u32,                                         // string_ids_off
            verify(le_u32, |size| *size <= 0xFFFF),         // type_ids_size
            le_u32,                                         // type_ids_off
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
            verify(le_u32, |size| *size <= 0xFFFF), // proto_ids_size
            le_u32,                                 // proto_ids_off
            le_u32,                                 // field_ids_size
            le_u32,                                 // field_ids_off
            le_u32,                                 // method_ids_size
            le_u32,                                 // method_ids_off
            le_u32,                                 // class_defs_size
            le_u32,                                 // class_defs_off
            le_u32,                                 // data_size
            le_u32,                                 // data_off
            cond(header.version >= DexVersion::DEX41, le_u32), // container_size
            cond(header.version >= DexVersion::DEX41, le_u32), // header_offset
        )
            .parse(remainder)?;

        Ok((remainder, header))
    }

    pub fn get_string_items(&self) -> Vec<&StringItem> {
        self.string_items
            .get_or_init(|| self.parse_string_items())
            .values()
            .map(|rc| rc.as_ref())
            .collect()
    }

    pub fn get_type_items(&self) -> Vec<&StringItem> {
        self.type_items
            .get_or_init(|| self.parse_type_items())
            .values()
            .map(|rc| rc.as_ref())
            .collect()
    }

    pub fn get_proto_items(&self) -> Vec<&ProtoItem> {
        self.proto_items
            .get_or_init(|| self.parse_proto_items())
            .values()
            .map(|rc| rc.as_ref())
            .collect()
    }

    pub fn get_field_items(&self) -> Vec<&FieldItem> {
        self.field_items
            .get_or_init(|| self.parse_field_items())
            .values()
            .map(|rc| rc.as_ref())
            .collect()
    }

    pub fn get_method_items(&self) -> Vec<&MethodItem> {
        self.method_items
            .get_or_init(|| self.parse_method_items())
            .values()
            .map(|rc| rc.as_ref())
            .collect()
    }

    pub fn get_class_items(&self) -> Vec<&ClassItem> {
        self.class_items
            .get_or_init(|| self.parse_class_items())
            .iter()
            .map(|rc| rc.as_ref())
            .collect()
    }

    pub fn get_map_items(&self) -> &MapList {
        self.map_items
            .get_or_init(|| self.parse_map_items().unwrap_or_default())
    }

    fn parse_string_items(&self) -> HashMap<u32, Rc<StringItem>> {
        (0..self.header.string_ids_size)
            .filter_map(|idx| {
                self.parse_string_by_id(idx)
                    .ok()
                    .map(|(_, item)| (idx, Rc::new(item)))
            })
            .collect()
    }

    fn parse_type_items(&self) -> HashMap<u32, Rc<StringItem>> {
        let mut remainder = &self.data[self.header.type_ids_off as usize..];

        let Some(string_items) = self.string_items.get() else {
            return HashMap::new();
        };

        (0..self.header.type_ids_size)
            .filter_map(|idx| {
                let (rem, descriptor_idx) =
                    le_u32::<&[u8], Error>(remainder).ok()?;
                remainder = rem;
                let item = string_items.get(&descriptor_idx)?;

                Some((idx, Rc::clone(item)))
            })
            .collect()
    }

    fn parse_proto_items(&self) -> HashMap<u32, Rc<ProtoItem>> {
        let (Some(string_items), Some(type_items)) =
            (self.string_items.get(), self.type_items.get())
        else {
            return HashMap::new();
        };

        let mut remainder = &self.data[self.header.proto_ids_off as usize
            ..self.header.field_ids_off as usize];

        (0..self.header.proto_ids_size)
            .filter_map(|idx| {
                let (rem, (shorty_idx, return_type_idx, parameters_idx)) = (
                    le_u32::<&[u8], Error>, // shorty_idx
                    le_u32,                 // return_type_idx
                    le_u32,                 // parameters_off
                )
                    .parse(remainder)
                    .ok()?;
                remainder = rem;

                let shorty_item = string_items.get(&shorty_idx)?;
                let return_type = type_items.get(&return_type_idx)?;

                let (parameters_count, parameters) = if parameters_idx == 0 {
                    (0, Vec::new())
                } else {
                    self.parse_type_list(parameters_idx)
                        .ok()
                        .map_or((0, Vec::new()), |(_, (size, types))| {
                            (size, types)
                        })
                };

                Some((
                    idx,
                    Rc::new(ProtoItem {
                        shorty: Rc::clone(shorty_item),
                        return_type: Rc::clone(return_type),
                        parameters_count,
                        parameters,
                    }),
                ))
            })
            .collect()
    }

    fn parse_field_items(&self) -> HashMap<u32, Rc<FieldItem>> {
        let (Some(string_items), Some(type_items)) =
            (self.string_items.get(), self.type_items.get())
        else {
            return HashMap::new();
        };

        let mut remainder = &self.data[self.header.field_ids_off as usize
            ..self.header.method_ids_off as usize];

        (0..self.header.field_ids_size)
            .filter_map(|idx| {
                let (rem, (class_idx, type_idx, name_idx)) = (
                    le_u16::<&[u8], Error>, // class_idx
                    le_u16,                 // type_idx
                    le_u32,                 // name_idx
                )
                    .parse(remainder)
                    .ok()?;
                remainder = rem;

                let class = Rc::clone(type_items.get(&(class_idx as u32))?);
                let type_ = Rc::clone(type_items.get(&(type_idx as u32))?);
                let name = Rc::clone(string_items.get(&name_idx)?);

                Some((idx, Rc::new(FieldItem { class, type_, name })))
            })
            .collect()
    }

    fn parse_method_items(&self) -> HashMap<u32, Rc<MethodItem>> {
        let (Some(string_items), Some(type_items), Some(proto_items)) = (
            self.string_items.get(),
            self.type_items.get(),
            self.proto_items.get(),
        ) else {
            return HashMap::new();
        };

        let mut remainder = &self.data[self.header.method_ids_off as usize
            ..self.header.class_defs_off as usize];

        (0..self.header.method_ids_size)
            .filter_map(|idx| {
                let (rem, (class_idx, proto_idx, name_idx)) = (
                    le_u16::<&[u8], Error>, // class_idx
                    le_u16,                 // proto_idx
                    le_u32,
                )
                    .parse(remainder)
                    .ok()?;
                remainder = rem;

                let class = Rc::clone(type_items.get(&(class_idx as u32))?);
                let proto = Rc::clone(proto_items.get(&(proto_idx as u32))?);
                let name = Rc::clone(string_items.get(&(name_idx as u32))?);

                Some((idx, Rc::new(MethodItem { class, proto, name })))
            })
            .collect()
    }

    fn parse_class_items(&self) -> Vec<Rc<ClassItem>> {
        if self.header.class_defs_off == 0 {
            return Vec::new();
        }

        let (Some(string_items), Some(type_items)) =
            (self.string_items.get(), self.type_items.get())
        else {
            return Vec::new();
        };

        let mut remainder = &self.data[self.header.class_defs_off as usize..];

        (0..self.header.class_defs_size)
            .filter_map(|_| {
                let (
                    rem,
                    (
                        class_idx,
                        access_flags,
                        superclass_idx,
                        _,
                        source_file_idx,
                    ),
                ) = (
                    le_u32::<&[u8], Error>, // class_idx
                    le_u32,                 // access_flags
                    le_u32,                 // superclass_idx
                    le_u32,                 // interfaces_off (unused)
                    le_u32,                 // source_file_idx
                )
                    .parse(remainder)
                    .ok()?;
                remainder = rem;

                let class = Rc::clone(type_items.get(&class_idx)?);
                let superclass = Rc::clone(type_items.get(&superclass_idx)?);
                let source_file =
                    Rc::clone(string_items.get(&source_file_idx)?);

                Some(Rc::new(ClassItem {
                    class,
                    access_flags,
                    superclass,
                    source_file,
                }))
            })
            .collect()
    }

    fn parse_type_list(
        &self,
        offset: u32,
    ) -> IResult<&[u8], (u32, Vec<Rc<StringItem>>)> {
        let type_items = self.type_items.get().unwrap();

        let mut remainder = &self.data[offset as usize..];
        let (type_list_rem, size) = le_u32(remainder)?;
        remainder = type_list_rem;

        let (_, type_indexes) =
            count(le_u32, size as usize).parse(remainder)?;

        let items = type_indexes
            .iter()
            .filter_map(|idx| match type_items.get(idx) {
                Some(item) => Some(Rc::clone(item)),
                None => None,
            })
            .collect();

        Ok((remainder, (size, items)))
    }

    fn parse_map_items(&self) -> Option<MapList> {
        let map_list_offset = &self.data[self.header.map_off as usize..];

        let (remainder, size) = match le_u32::<&[u8], Error>(map_list_offset) {
            Ok(item) => item,
            Err(_) => return None,
        };

        let (_, items) = match count(Self::parse_map_item, size as usize)
            .parse(remainder)
        {
            Ok(item) => item,
            Err(_) => return None,
        };

        Some(MapList { size, items })
    }

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

    fn parse_string_by_id(&self, idx: u32) -> IResult<&[u8], StringItem> {
        let string_idx_offset =
            &self.data[(self.header.string_ids_off + idx * 4) as usize..];

        let (_, string_data_off) = le_u32(string_idx_offset)?;

        let string_data = &self.data[string_data_off as usize..];

        let (string_data, utf16_size) = uleb128(string_data)?;
        let (string_data, bytes) = take(utf16_size)(string_data)?;
        let s = std::str::from_utf8(bytes).unwrap_or_default().to_string();

        Ok((string_data, StringItem { size: utf16_size, value: s }))
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

impl Into<u32> for DexVersion {
    fn into(self) -> u32 {
        match self {
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
pub struct StringItem {
    size: u64,     // uleb128 size
    value: String, // ubyte[]
}

#[derive(Debug)]
pub struct ProtoItem {
    shorty: Rc<StringItem>,
    return_type: Rc<StringItem>,
    parameters_count: u32,
    parameters: Vec<Rc<StringItem>>,
}

#[derive(Debug)]
pub struct FieldItem {
    class: Rc<StringItem>,
    type_: Rc<StringItem>,
    name: Rc<StringItem>,
}

#[derive(Debug)]
pub struct MethodItem {
    class: Rc<StringItem>,
    proto: Rc<ProtoItem>,
    name: Rc<StringItem>,
}

#[derive(Debug)]
pub struct ClassItem {
    class: Rc<StringItem>,
    access_flags: u32,
    superclass: Rc<StringItem>,
    source_file: Rc<StringItem>,
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

// TODO: maybe move this functions from macho and this module in utils
/// Parser that reads [ULEB128][1].
///
/// Notice however that this function returns a `u64`, so it's able to parse
/// numbers up to 2^64-1. When parsing larger numbers it fails, even if they
/// are valid ULEB128.
///
/// [1]: https://en.wikipedia.org/wiki/LEB128
fn uleb128(input: &[u8]) -> IResult<&[u8], u64> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;

    let mut data = input;
    let mut byte: u8;

    loop {
        // Read one byte of data.
        (data, byte) = u8(data)?;

        // Use all the bits, except the most significant one.
        let b = (byte & 0x7f) as u64;

        val |= b
            .checked_shl(shift)
            .ok_or(Err::Error(Error::new(input, ErrorKind::TooLarge)))?;

        // Break if the most significant bit is zero.
        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
    }

    Ok((data, val))
}

impl From<Dex<'_>> for protos::dex::Dex {
    fn from(dex: Dex) -> Self {
        let mut result = protos::dex::Dex::new();

        result.set_is_dex(true);
        // TODO: think about borrowing, idk what is the best for now
        result.header = MessageField::some(dex.header.clone().into());

        result.string_items.extend(
            dex.get_string_items()
                .into_iter()
                .map(protos::dex::StringItem::from),
        );
        result.types.extend(
            dex.get_type_items()
                .into_iter()
                .map(protos::dex::StringItem::from),
        );
        result.protos.extend(
            dex.get_proto_items()
                .into_iter()
                .map(protos::dex::ProtoItem::from),
        );
        result.fields.extend(
            dex.get_field_items()
                .into_iter()
                .map(protos::dex::FieldItem::from),
        );
        result.methods.extend(
            dex.get_method_items()
                .into_iter()
                .map(protos::dex::MethodItem::from),
        );
        result.classes.extend(
            dex.get_class_items()
                .into_iter()
                .map(protos::dex::ClassItem::from),
        );

        result.map_list = MessageField::some(dex.get_map_items().into());

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

impl From<&StringItem> for protos::dex::StringItem {
    fn from(item: &StringItem) -> Self {
        let mut result = protos::dex::StringItem::new();

        result.set_size(item.size);
        result.set_value(item.value.to_string());
        result
    }
}

impl From<&ProtoItem> for protos::dex::ProtoItem {
    fn from(value: &ProtoItem) -> Self {
        let mut result = protos::dex::ProtoItem::new();

        result.shorty = MessageField::some(value.shorty.as_ref().into());
        result.return_type =
            MessageField::some(value.return_type.as_ref().into());
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

        result.class = MessageField::some(value.class.as_ref().into());
        result.type_ = MessageField::some(value.type_.as_ref().into());
        result.name = MessageField::some(value.name.as_ref().into());

        result
    }
}

impl From<&MethodItem> for protos::dex::MethodItem {
    fn from(value: &MethodItem) -> Self {
        let mut result = protos::dex::MethodItem::new();

        result.class = MessageField::some(value.class.as_ref().into());
        result.proto = MessageField::some(value.proto.as_ref().into());
        result.name = MessageField::some(value.name.as_ref().into());

        result
    }
}

impl From<&ClassItem> for protos::dex::ClassItem {
    fn from(value: &ClassItem) -> Self {
        let mut result = protos::dex::ClassItem::new();

        result.class = MessageField::some(value.class.as_ref().into());
        result.set_access_flags(value.access_flags);
        result.superclass =
            MessageField::some(value.superclass.as_ref().into());
        result.source_file =
            MessageField::some(value.source_file.as_ref().into());

        result
    }
}

impl From<&MapList> for protos::dex::MapList {
    fn from(value: &MapList) -> Self {
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

        result.type_ = item
            .item_type
            .try_into()
            .ok()
            .map(EnumOrUnknown::<protos::dex::TypeCode>::from_i32);
        result.set_unused(item.unused.into());
        result.set_size(item.size);
        result.set_offset(item.offset);

        result
    }
}
