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

/// Tracks cumulative heap and struct memory allocated while parsing a DEX file
/// so that crafted files with overlapping offsets or shared indices cannot
/// amplify small inputs into multi-gigabyte allocations.
struct MemoryBudget {
    remaining: usize,
}

impl MemoryBudget {
    #[inline]
    fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    #[inline]
    fn try_consume(&mut self, bytes: usize) -> bool {
        if bytes <= self.remaining {
            self.remaining -= bytes;
            true
        } else {
            false
        }
    }

    #[inline]
    fn refund(&mut self, bytes: usize) {
        self.remaining = self.remaining.saturating_add(bytes);
    }
}

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
    const MAX_MAP_ITEMS: usize = 10_000;

    /// Maximum cumulative memory (in bytes) and maximum expansion factor
    /// relative to input size that [`Dex::parse`] will allocate across
    /// strings, types, prototypes, fields, methods, classes, and map items.
    const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
    const MAX_EXPANSION_FACTOR: usize = 128;

    /// Fixed per-item overhead constants (matching 64-bit Rust struct layouts)
    /// so that budget truncation is deterministic across 32-bit and 64-bit
    /// targets.
    const STRING_OVERHEAD: usize = 24;
    const PROTO_OVERHEAD: usize = 96;
    const FIELD_OVERHEAD: usize = 88;
    const METHOD_OVERHEAD: usize = 72;
    const CLASS_OVERHEAD: usize = 96;
    const MAP_ITEM_OVERHEAD: usize = 48;

    #[inline]
    fn vec_string_cost(len: usize) -> usize {
        Self::STRING_OVERHEAD.saturating_add(len)
    }

    /// Returns the item at `idx` in a table that keeps one slot per index
    /// of the DEX file, or `None` if the index is out of range or the item
    /// couldn't be parsed.
    #[inline]
    fn lookup<T>(items: &[Option<T>], idx: u32) -> Option<&T> {
        items.get(idx as usize)?.as_ref()
    }

    pub fn parse(data: &[u8]) -> Result<protos::dex::Dex, Err<Error<'_>>> {
        // Extract dex header with information about data location
        let (_, header) = Self::parse_dex_header(data)?;

        let budget_limit = data
            .len()
            .saturating_mul(Self::MAX_EXPANSION_FACTOR)
            .min(Self::MAX_TOTAL_BYTES);
        let mut budget = MemoryBudget::new(budget_limit);

        // Extract defined strings
        let strings = Self::parse_strings(data, &header, &mut budget);

        // Extract defined types
        let types = Self::parse_types(data, &header, &strings, &mut budget);

        // Extract defined prototypes
        let (protos, proto_costs) =
            Self::parse_protos(data, &header, &strings, &types, &mut budget);

        // Extract defined fields
        let fields =
            Self::parse_fields(data, &header, &strings, &types, &mut budget);

        // Extract defined methods
        let methods = Self::parse_methods(
            data,
            &header,
            &strings,
            &types,
            &protos,
            &proto_costs,
            &mut budget,
        );

        // Extract defined classes
        let class_defs = Self::parse_class_defs(
            data,
            &header,
            &strings,
            &types,
            &mut budget,
        );

        // Extract map information
        let map_list = Self::parse_map_items(data, &header, &mut budget);

        let mut dex = protos::dex::Dex::new();
        dex.set_is_dex(true);

        dex.header = MessageField::some(header.into());
        // The tables above keep one slot per index of the DEX file, so that
        // an entry that can't be parsed doesn't shift the indices of the
        // following ones. Only the entries that were parsed are exposed.
        dex.strings = strings.into_iter().flatten().collect();
        dex.types = types.into_iter().flatten().collect();
        dex.protos = protos.into_iter().flatten().collect();
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

    /// Collects the strings referenced by the string_ids_off list.
    ///
    /// The result has one slot per entry in string_ids, so that types, fields,
    /// methods and classes can look up strings by their index in the DEX
    /// file. A string that can't be parsed leaves a `None` in its slot
    /// instead of shifting the indices of the strings that follow it.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#string-item
    fn parse_strings(
        data: &[u8],
        header: &DexHeader,
        budget: &mut MemoryBudget,
    ) -> Vec<Option<String>> {
        // DEX file doesn't contain strings.
        // It's a strange case, but it needs to be checked.
        if header.string_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.string_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        let mut strings = Vec::new();

        for offset in iterator(table_slice, le_u32::<&[u8], Error>)
            .take(Self::MAX_STRINGS)
            .take(header.string_ids_size as usize)
        {
            match Self::parse_string_from_offset(data, offset, budget) {
                Ok(Some(s)) => strings.push(Some(s)),
                Ok(None) => {
                    if !budget.try_consume(Self::STRING_OVERHEAD) {
                        break;
                    }
                    strings.push(None)
                }
                Err(()) => break,
            }
        }

        strings
    }

    /// Parses string by index in the string_ids_off table
    ///
    /// idx - is an index in the string_ids_off table
    /// strings_ids_off[idx] -> string_data_item
    ///
    /// Strings longer than 65,536 UTF-16 code units will be considered invalid
    /// and the result will be `Ok(None)`. Returns `Err(())` if the cumulative
    /// memory budget is exhausted.
    fn parse_string_from_offset(
        data: &[u8],
        string_data_offset: u32,
        budget: &mut MemoryBudget,
    ) -> Result<Option<String>, ()> {
        if string_data_offset < Self::DEX_HEADER_SIZE {
            return Ok(None);
        }

        let Some(slice) = data.get(string_data_offset as usize..) else {
            return Ok(None);
        };

        let Ok((slice, utf16_size)) = uleb128(slice) else {
            return Ok(None);
        };

        if utf16_size > 65536 || (utf16_size as usize) > data.len() {
            return Ok(None);
        }

        // `utf16_size` is the length of the string in UTF-16 code units, not
        // in bytes: each code unit takes 1 to 3 bytes in MUTF-8. The string
        // data ends with a null byte, which MUTF-8 never uses inside a
        // string (U+0000 is encoded as 0xC0 0x80), so the string spans up to
        // that terminator, looked for within the longest possible encoding.
        let max_len = (utf16_size as usize).saturating_mul(3);
        let window = &slice[..slice.len().min(max_len.saturating_add(1))];
        let Some(end) = memchr::memchr(0, window) else {
            // Charge the scanned window so repeated unterminated entries
            // cannot cause unbounded scanning work.
            if !budget.try_consume(window.len()) {
                return Err(());
            }
            return Ok(None);
        };
        let bytes = &window[..end];

        // Charge the input slice size upfront before MUTF-8 decoding so that
        // repeated invalid MUTF-8 entries cannot cause unbounded decoding work.
        let reserved = Self::vec_string_cost(bytes.len());
        if !budget.try_consume(reserved) {
            return Err(());
        }

        // Decode MUTF-8 string and return String
        match simd_cesu8::mutf8::decode(bytes) {
            Ok(s) => {
                let s = s.into_owned();
                let actual = Self::vec_string_cost(s.len());
                if reserved > actual {
                    budget.refund(reserved - actual);
                }
                Ok(Some(s))
            }
            Err(_) => Ok(None),
        }
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
        string_items: &[Option<String>],
        budget: &mut MemoryBudget,
    ) -> Vec<Option<String>> {
        // DEX file doesn't contain types.
        // It's a strange case, but it needs to be checked.
        if header.type_ids_off == 0 {
            return Vec::new();
        }

        let table_slice = match data.get(header.type_ids_off as usize..) {
            Some(slice) => slice,
            None => return Vec::new(),
        };

        let mut types = Vec::new();

        for idx in iterator(table_slice, le_u32::<&[u8], Error>)
            .take(Self::MAX_TYPES)
            .take(header.type_ids_size as usize)
        {
            // Keep one slot per type index, even when the type's string is
            // missing, so that the indices of the following types still match.
            let s = Self::lookup(string_items, idx);
            let cost = s.map_or(Self::STRING_OVERHEAD, |s| {
                Self::vec_string_cost(s.len())
            });
            if !budget.try_consume(cost) {
                break;
            }
            types.push(s.cloned());
        }

        types
    }

    /// Collects a list of prototypes in a hashmap from proto_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#proto-id-item
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-list
    fn parse_protos(
        data: &[u8],
        header: &DexHeader,
        string_items: &[Option<String>],
        type_items: &[Option<String>],
        budget: &mut MemoryBudget,
    ) -> (Vec<Option<protos::dex::ProtoItem>>, Vec<usize>) {
        // DEX file doesn't contain prototypes.
        // It's a strange case, but it needs to be checked.
        if header.proto_ids_off == 0 {
            return (Vec::new(), Vec::new());
        }

        let table_slice = match data.get(header.proto_ids_off as usize..) {
            Some(slice) => slice,
            None => return (Vec::new(), Vec::new()),
        };

        let mut protos = Vec::new();
        let mut proto_costs = Vec::new();

        for (shorty_idx, return_type_idx, parameters_off) in
            iterator(table_slice, (le_u32::<&[u8], Error>, le_u32, le_u32))
                .take(Self::MAX_PROTOS)
                .take(header.proto_ids_size as usize)
        {
            // As with strings and types, a prototype that can't be resolved
            // keeps its slot so that methods still find theirs by index.
            let (Some(shorty), Some(return_type)) = (
                Self::lookup(string_items, shorty_idx),
                Self::lookup(type_items, return_type_idx),
            ) else {
                if !budget.try_consume(Self::PROTO_OVERHEAD) {
                    break;
                }
                protos.push(None);
                proto_costs.push(0);
                continue;
            };

            let checkpoint = budget.remaining;
            let mut item_cost = Self::PROTO_OVERHEAD
                .saturating_add(shorty.len())
                .saturating_add(return_type.len());

            if !budget.try_consume(item_cost) {
                break;
            }

            // According to the documentation, if parameters_off is 0, then
            // the type has 0 parameters.
            let parameters = if parameters_off == 0 {
                Vec::new()
            } else {
                match Self::parse_type_list(
                    data,
                    type_items,
                    parameters_off,
                    budget,
                    &mut item_cost,
                ) {
                    Ok(params) => params.unwrap_or_default(),
                    Err(()) => {
                        budget.remaining = checkpoint;
                        break;
                    }
                }
            };

            let mut item = protos::dex::ProtoItem::new();
            item.shorty = Some(shorty.clone());
            item.return_type = Some(return_type.clone());
            item.set_parameters_count(parameters.len() as u32);
            item.parameters = parameters;

            protos.push(Some(item));
            proto_costs.push(item_cost);
        }

        (protos, proto_costs)
    }

    /// Collects a type list to list of strings from given offset
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#type-list
    fn parse_type_list(
        data: &[u8],
        type_items: &[Option<String>],
        offset: u32,
        budget: &mut MemoryBudget,
        item_cost: &mut usize,
    ) -> Result<Option<Vec<String>>, ()> {
        let Some(remainder) = data.get(offset as usize..) else {
            return Ok(None);
        };
        let Ok((remainder, size)) = le_u32::<&[u8], Error>(remainder) else {
            return Ok(None);
        };

        // The number of arguments can't be higher than 255 due to constraints
        // in the Dalvik bytecode instruction set itself.
        if size > 255 {
            return Ok(None);
        }

        let mut params = Vec::new();
        for idx in iterator(remainder, le_u16::<&[u8], Error>)
            .take(size as usize)
        {
            let Some(t) = Self::lookup(type_items, idx.into()) else {
                continue;
            };
            let param_cost = Self::vec_string_cost(t.len());
            if !budget.try_consume(param_cost) {
                return Err(());
            }
            *item_cost = item_cost.saturating_add(param_cost);
            params.push(t.clone());
        }

        Ok(Some(params))
    }

    /// Collects a list of fields in a hashmap from field_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#field-id-item
    fn parse_fields(
        data: &[u8],
        header: &DexHeader,
        string_items: &[Option<String>],
        type_items: &[Option<String>],
        budget: &mut MemoryBudget,
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

        let mut fields = Vec::new();

        for (class_idx, type_idx, name_idx) in
            iterator(table_slice, (le_u16::<&[u8], Error>, le_u16, le_u32))
                .take(Self::MAX_FIELDS)
                .take(header.field_ids_size as usize)
        {
            let Some(class) = Self::lookup(type_items, class_idx.into()) else {
                continue;
            };
            let Some(type_) = Self::lookup(type_items, type_idx.into()) else {
                continue;
            };
            let Some(name) = Self::lookup(string_items, name_idx) else {
                continue;
            };

            let cost = Self::FIELD_OVERHEAD
                .saturating_add(class.len())
                .saturating_add(type_.len())
                .saturating_add(name.len());

            if !budget.try_consume(cost) {
                break;
            }

            let mut item = protos::dex::FieldItem::new();
            item.class = Some(class.clone());
            item.type_ = Some(type_.clone());
            item.name = Some(name.clone());
            fields.push(item);
        }

        fields
    }

    /// Collects a list of methods in a hashmap from method_ids_off list.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#method-id-item
    fn parse_methods(
        data: &[u8],
        header: &DexHeader,
        string_items: &[Option<String>],
        type_items: &[Option<String>],
        proto_items: &[Option<protos::dex::ProtoItem>],
        proto_costs: &[usize],
        budget: &mut MemoryBudget,
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

        let mut methods = Vec::new();

        for (class_idx, proto_idx, name_idx) in
            iterator(table_slice, (le_u16::<&[u8], Error>, le_u16, le_u32))
                .take(Self::MAX_METHODS)
                .take(header.method_ids_size as usize)
        {
            let Some(class) = Self::lookup(type_items, class_idx.into()) else {
                continue;
            };
            let Some(proto) = Self::lookup(proto_items, proto_idx.into()) else {
                continue;
            };
            let proto_cost = proto_costs[proto_idx as usize];
            let Some(name) = Self::lookup(string_items, name_idx) else {
                continue;
            };

            let cost = Self::METHOD_OVERHEAD
                .saturating_add(class.len())
                .saturating_add(proto_cost)
                .saturating_add(name.len());

            if !budget.try_consume(cost) {
                break;
            }

            let mut item = protos::dex::MethodItem::new();
            item.class = Some(class.clone());
            item.proto = MessageField::some(proto.clone());
            item.name = Some(name.clone());
            methods.push(item);
        }

        methods
    }

    /// Collects a list of classes from class_defs_off list.
    /// Only a part of the fields is extracted, because not all of them are
    /// useful when writing YARA rules.
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#class-def-item
    fn parse_class_defs(
        data: &[u8],
        header: &DexHeader,
        string_items: &[Option<String>],
        type_items: &[Option<String>],
        budget: &mut MemoryBudget,
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

        let mut classes = Vec::new();

        for (
            class_idx,
            access_flags,
            superclass_idx,
            _,
            source_file_idx,
            _,
            _,
            _,
        ) in it.take(Self::MAX_CLASSES).take(header.class_defs_size as usize)
        {
            let Some(class) = Self::lookup(type_items, class_idx) else {
                continue;
            };
            let superclass = if superclass_idx != Self::NO_INDEX {
                Self::lookup(type_items, superclass_idx)
            } else {
                None
            };
            let source_file = if source_file_idx != Self::NO_INDEX {
                Self::lookup(string_items, source_file_idx)
            } else {
                None
            };

            let cost = Self::CLASS_OVERHEAD
                .saturating_add(class.len())
                .saturating_add(superclass.map_or(0, String::len))
                .saturating_add(source_file.map_or(0, String::len));

            if !budget.try_consume(cost) {
                break;
            }

            let mut item = protos::dex::ClassItem::new();
            item.class = Some(class.clone());
            item.set_access_flags(access_flags);
            if let Some(superclass) = superclass {
                item.superclass = Some(superclass.clone());
            }
            if let Some(source_file) = source_file {
                item.source_file = Some(source_file.clone());
            }
            classes.push(item);
        }

        classes
    }

    /// Collects information about maps from the DEX file
    ///
    /// See: https://source.android.com/docs/core/runtime/dex-format#map-list
    fn parse_map_items(
        data: &[u8],
        header: &DexHeader,
        budget: &mut MemoryBudget,
    ) -> Option<protos::dex::MapList> {
        if header.map_off < Self::DEX_HEADER_SIZE {
            return None;
        }

        data.get(header.map_off as usize..).and_then(|offset| {
            let (items_offset, size) = le_u32::<&[u8], Error>(offset).ok()?;
            let mut items = Vec::new();

            for item in iterator(items_offset, Self::parse_map_item)
                .take(Self::MAX_MAP_ITEMS)
                .take(size as usize)
            {
                if !budget.try_consume(Self::MAP_ITEM_OVERHEAD) {
                    break;
                }
                items.push(item);
            }

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
