use std::borrow::Cow;
use std::cell::OnceCell;
use std::cmp::min;
use std::ffi::CStr;
use std::fmt::{Display, Formatter, Write};
use std::str::from_utf8;

use bits::complete::tag as bits_tag;
use bits::complete::take as bits_take;
use nom::branch::alt;
use nom::bytes::complete::{take, take_till};
use nom::combinator::{cond, map, map_opt, map_parser, map_res, verify};
use nom::multi::{count, length_count, length_data, many_m_n, many0};
use nom::number::complete::{le_u16, le_u32, le_u64, u8};
use nom::{IResult, Parser, bits};
use num_derive::FromPrimitive;
use num_traits;
use protobuf::MessageField;
use uuid::Uuid;

use crate::modules::pe::parser::{DirEntry, PE};
use crate::modules::protos;

use strum_macros::Display;

type NomError<'a> = nom::error::Error<&'a [u8]>;
#[derive(Display)]
pub enum Error<'a> {
    InvalidDotNet,
    InvalidCodedIndex,
    InvalidType,
    RecursionLimit,
    Parse(nom::Err<NomError<'a>>),
    OutputWrite(std::fmt::Error),
}

impl From<std::fmt::Error> for Error<'_> {
    fn from(value: std::fmt::Error) -> Self {
        Self::OutputWrite(value)
    }
}

impl<'a> From<nom::Err<NomError<'a>>> for Error<'a> {
    fn from(value: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        Self::Parse(value)
    }
}

/// An .NET file parser.
#[derive(Default)]
pub struct Dotnet<'a> {
    /// Slice that contains the whole .NET file.
    data: &'a [u8],
    /// Version string.
    version: &'a str,
    /// Headers of the streams found in the .NET file.
    stream_headers: Vec<StreamHeader<'a>>,
    /// Size of indexes used for referencing a string in the `#Strings` stream.
    string_index_size: IndexSize,
    /// Size of indexes used for referencing a blob in the `#Blob` stream.
    blob_index_size: IndexSize,
    /// Size of the indexes used for referencing a GUID in the `#GUID` stream.
    guid_index_size: IndexSize,
    /// Vector that contains the number of rows on each table. Indexes in this
    /// vector corresponds table numbers [`Table::Module`], [`Table::TypeRef`],
    /// [`Table::TypeDef`], etc.
    num_rows: Vec<usize>,
    /// Slice containing all the .NET resources.
    raw_resources: Option<&'a [u8]>,
    /// Offset of `raw_resources` relative to the start of the PE file. If the
    /// offset could not be computed it is [`None`].
    raw_resources_offset: Option<u32>,
    /// Index within `stream_headers` for the `#Strings` stream.
    strings_stream: Option<usize>,
    /// Index within `stream_headers` for the `#US` stream.
    us_stream: Option<usize>,
    /// Index within `stream_headers` for the `#Blob` stream.
    blob_stream: Option<usize>,
    /// Index within `stream_headers` for the `#GUID` stream.
    guid_stream: Option<usize>,
    /// GUIDs found in the `#GUID` stream.
    guids: OnceCell<Option<Vec<Uuid>>>,
    /// User types.
    user_types: OnceCell<Vec<Class<'a>>>,
    /// All strings in the `#US` stream.
    user_strings: OnceCell<Vec<&'a [u8]>>,
    /// The value of a custom attribute named `GuidAttribute`.
    typelib: OnceCell<Option<&'a str>>,
    /// Modules table.
    modules: Vec<Option<&'a str>>,
    /// TypeRef table.
    type_refs: Vec<TypeRef<'a>>,
    /// TypeDef table.
    type_defs: Vec<TypeDef<'a>>,
    /// TypeSpec table.
    type_specs: Vec<BlobIndex>,
    /// MemberRef table.
    member_refs: Vec<MemberRef>,
    /// InterfaceImpl table.
    interface_impls: Vec<InterfaceImpl>,
    /// FieldRVA table.
    field_rvas: Vec<u32>,
    /// field_rvas after converting them to file offsets. This vector can
    /// contain fewer items than field_rvas, if some RVA can't be converted
    /// to an offset.
    field_offsets: Vec<u32>,
    /// Constant table.
    constants: Vec<Constant<'a>>,
    /// CustomAttribute table.
    custom_attributes: Vec<CustomAttribute<'a>>,
    /// ModuleRef table.
    module_refs: Vec<Option<&'a str>>,
    /// Assembly table.
    assemblies: Vec<Assembly<'a>>,
    /// AssemblyRef table.
    assembly_refs: Vec<AssemblyRef<'a>>,
    /// Resource table.
    resources: Vec<Resource<'a>>,
    /// NestedClass table.
    nested_classes: Vec<NestedClass>,
    /// GenericParam table.
    generic_params: Vec<GenericParam<'a>>,
    /// Param table.
    params: Vec<Param<'a>>,
    /// MethodDef table.
    method_defs: Vec<MethodDef<'a>>,
}

impl<'a> Dotnet<'a> {
    /// Parses a .NET file and produces a [`Dotnet`] structure containing
    /// metadata extracted from the file.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error<'a>> {
        let pe = PE::parse(data)?;

        let (_, _, cli_header) = pe
            .get_dir_entry_data(
                PE::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
                false,
            )
            .ok_or(Error::InvalidDotNet)?;

        let (_, cli_header) = Self::parse_cli_header(cli_header)?;

        let raw_metadata_offset = pe
            .rva_to_offset(cli_header.metadata.addr)
            .ok_or(Error::InvalidDotNet)?;

        let raw_metadata = pe
            .data_at_rva_with_size(
                cli_header.metadata.addr,
                cli_header.metadata.size as usize,
            )
            .ok_or(Error::InvalidDotNet)?;

        let raw_resources_offset = pe.rva_to_offset(cli_header.resources.addr);

        let raw_resources = pe.data_at_rva_with_size(
            cli_header.resources.addr,
            cli_header.resources.size as usize,
        );

        let (_, mut metadata) = Self::parse_metadata_root(raw_metadata)?;

        let mut tilde_stream = None;
        let mut strings_stream = None;
        let mut us_stream = None;
        let mut blob_stream = None;
        let mut guid_stream = None;

        for (i, header) in metadata.stream_headers.iter_mut().enumerate() {
            // Offsets in stream headers are relative to the start of the
            // metadata, but here we make them relative to the start of the
            // file.
            header.offset = header.offset.saturating_add(raw_metadata_offset);

            match header.name {
                // Tilde stream, the "#-" name is not documented, but
                // represents an unoptimized metadata stream.
                b"#~" | b"#-" => tilde_stream = Some(i),
                // Contains null-terminated UTF-8 strings that are referenced
                // from other streams.
                b"#Strings" => strings_stream = Some(i),
                // US comes from user string. Contains UTF-16 strings.
                b"#US" => us_stream = Some(i),
                // Contains sequences of bytes.
                b"#Blob" => blob_stream = Some(i),
                // Contains a sequence of 128-bits GUIDs.
                b"#GUID" => guid_stream = Some(i),
                // Ignore streams with unknown names.
                _ => {}
            }
        }

        let mut dotnet = Self {
            data,
            stream_headers: metadata.stream_headers,
            version: metadata.version,
            raw_resources,
            raw_resources_offset,
            strings_stream,
            us_stream,
            blob_stream,
            guid_stream,
            ..Default::default()
        };

        // Parse the `#~` stream. The stream can be missing or the parsing can
        // fail, but the file is still considered a valid .NET file.
        let _ = tilde_stream
            .and_then(|index| dotnet.get_stream(index))
            .map(|tilde_stream| dotnet.parse_tilde_stream(tilde_stream));

        dotnet.field_offsets = std::mem::take(&mut dotnet.field_rvas)
            .into_iter()
            .filter_map(|rva| pe.rva_to_offset(rva))
            .collect();

        Ok(dotnet)
    }

    pub fn get_guids(&self) -> impl Iterator<Item = &Uuid> {
        self.guids
            .get_or_init(|| self.parse_guids())
            .as_deref()
            .unwrap_or_default()
            .iter()
    }

    pub fn get_user_types(&self) -> impl Iterator<Item = &Class<'a>> {
        self.user_types
            .get_or_init(|| self.parse_user_types())
            .as_slice()
            .iter()
    }

    pub fn get_user_strings(&self) -> impl Iterator<Item = &&[u8]> {
        self.user_strings
            .get_or_init(|| self.parse_user_strings())
            .as_slice()
            .iter()
    }

    pub fn get_string_constants(&self) -> impl Iterator<Item = &[u8]> {
        self.constants.iter().filter_map(|c| {
            if c.type_ == Type::String { c.value } else { None }
        })
    }

    pub fn get_typelib(&self) -> Option<&'a str> {
        *self.typelib.get_or_init(|| self.parse_typelib())
    }
}

impl<'a> Dotnet<'a> {
    const MAX_PARAMS: u32 = 1000;
    const MAX_ROWS_PER_TABLE: usize = 15000;
    const MAX_ARRAY_DIMENSION: u32 = 50;
    const MAX_RECURSION: usize = 16;
    const MAX_TYPE_NAME_LEN: usize = 16 * 1024;
    const MAX_METHOD_SIG_BYTES: usize = 32 * 1024 * 1024;
    const PARAM_OVERHEAD_BYTES: usize = 64;

    /// Given an index into the `#Strings` stream, returns the string.
    fn get_string(&self, index: StringIndex) -> Option<&'a str> {
        CStr::from_bytes_until_nul(
            self.get_stream(self.strings_stream?)?.get(index.0 as usize..)?,
        )
        .ok()
        .and_then(|s| s.to_str().ok())
    }

    /// Given an index into the `#Blob` stream, returns the blob's data.
    ///
    /// ECMA-335 II.24.2.4
    fn get_blob(&self, index: BlobIndex) -> Option<&'a [u8]> {
        let blob_stream = self.get_stream(self.blob_stream?)?;
        let data = blob_stream.get(index.0 as usize..)?;
        let (data, length) = var_uint(data).ok()?;
        data.get(0..length as usize)
    }

    /// Returns the raw data for the stream that has the given `index` in the
    /// streams table.
    fn get_stream(&self, index: usize) -> Option<&'a [u8]> {
        let header = self.stream_headers.get(index)?;
        let start_offset = header.offset as usize;
        let end_offset = start_offset.saturating_add(header.size as usize);
        self.data.get(start_offset..end_offset)
    }

    #[inline]
    fn num_rows(&self, table: Table) -> usize {
        self.num_rows[table as usize]
    }

    fn get_type_ref(&self, index: &CodedIndex) -> Option<&TypeRef<'a>> {
        if index.table != Table::TypeRef {
            return None;
        }
        self.type_refs.get(index.index)
    }

    fn get_type_spec(&self, index: &CodedIndex) -> Option<&BlobIndex> {
        if index.table != Table::TypeSpec {
            return None;
        }
        self.type_specs.get(index.index)
    }

    fn get_member_ref(&self, index: &CodedIndex) -> Option<&MemberRef> {
        if index.table != Table::MemberRef {
            return None;
        }
        self.member_refs.get(index.index)
    }
}

impl<'a> Dotnet<'a> {
    fn parse_cli_header(input: &[u8]) -> IResult<&[u8], CLIHeader> {
        map(
            (
                // CLI header is always 72 bytes long.
                verify(le_u32, |size| *size == 72), // size
                le_u16,                             // major_runtime_version
                le_u16,                             // minor_runtime_version
                PE::parse_dir_entry,                // metadata
                le_u32,                             // flags
                le_u32,                             // entry_point_token
                PE::parse_dir_entry,                // resources,
                PE::parse_dir_entry,                // strong_name_signature
            ),
            |(
                _,
                _major_runtime_version,
                _minor_runtime_version,
                metadata,
                _flags,
                _entry_point_token,
                resources,
                _strong_name_signature,
            )| { CLIHeader { metadata, resources } },
        )
        .parse(input)
    }

    /// Parses metadata root.
    ///
    /// ECMA-335 Section II.24.2.1.
    fn parse_metadata_root(input: &[u8]) -> IResult<&[u8], CLIMetadata<'_>> {
        map(
            (
                verify(le_u32, |magic| *magic == 0x424A5342), // magic == 0x424A5342
                le_u16,                                       // major_version
                le_u16,                                       // minor_version
                le_u32,                                       // reserved
                // length + version string. According to the specification
                // length must be <= 255. The length includes any padding
                // added to align the next field to a 4 byte boundary. The
                // string is UTF-8 and null-terminated.
                map_res(
                    map_parser(
                        length_data(verify(le_u32, |length| *length <= 255)),
                        take_till(|c| c == 0),
                    ),
                    from_utf8,
                ),
                le_u16, // flags (reserved)
                // number of streams, say N, followed by array of N stream
                // headers. The specification doesn't set a limit to the number
                // of streams, but as a sanity check we make sure it doesn't
                // exceed 256. There are files with 163 streams, like
                // 6d72a599724c4ff367b2c00b48030a62d286de5493c25c000a00f5fbc6e7b746
                length_count(
                    verify(le_u16, |n| *n <= 256),
                    Self::parse_stream_header,
                ),
            ),
            |(
                _magic,
                _major_version,
                _minor_version,
                _reserved,
                version,
                _flags,
                stream_headers,
            )| { CLIMetadata { stream_headers, version } },
        )
        .parse(input)
    }

    /// Parses a stream header.
    fn parse_stream_header(input: &[u8]) -> IResult<&[u8], StreamHeader<'_>> {
        let (remaining, (offset, size, name)) = (
            le_u32,                // offset
            le_u32,                // size
            take_till(|c| c == 0), // name, null-terminated ASCII string
        )
            .parse(input)?;

        // The name is padded with zeroes up to the next 4 bytes boundary,
        // lets consume the padding, which includes the null-terminator.
        let padding = (name.len() + 1).next_multiple_of(4) - name.len();

        let (remaining, _) = take(padding)(remaining)?;

        Ok((remaining, StreamHeader { offset, size, name }))
    }

    /// Parses the `#GUID` stream and returns the GUIDs.
    ///
    /// Returns a maximum of 16 GUIDs, ignoring the rest if there are more.
    fn parse_guids(&self) -> Option<Vec<Uuid>> {
        let guid_stream = self.get_stream(self.guid_stream?)?;

        let (_, guids) = many_m_n(
            0,
            16, // returns up to 16 GUIDs.
            map_res(
                take::<u8, &[u8], nom::error::Error<&'a [u8]>>(16_u8),
                Uuid::from_slice_le,
            ),
        )
        .parse(guid_stream)
        .ok()?;

        Some(guids)
    }

    /// Parse the `#~` stream.
    ///
    /// The `#~` stream contains all the tables, after parsing this stream
    /// all tables in the [`Dotnet`] structure are populated.
    ///
    /// ECMA-335 Section II.24.2.6.
    fn parse_tilde_stream(
        &mut self,
        input: &'a [u8],
    ) -> IResult<&'a [u8], ()> {
        // The `#~` starts with a header that is followed by the tables.
        let (remainder, (_, _, _, heap_sizes, _, valid, _sorted)) = (
            le_u32, // reserved, always 0
            u8,     // major_version, shall be 2
            u8,     // minor_version; shall be 0
            u8,     // heap_sizes
            u8,     // reserved, always 1
            le_u64, // valid
            le_u64, // sorted
        )
            .parse(input)?;

        // The number of tables is the number of bits set to 1 in the `valid`
        // field.
        let num_tables = u64::count_ones(valid);

        // Then follows an array of `num_tables` items with the number of rows
        // per each table that is present.
        let (mut remainder, num_rows_per_present_table) =
            count(map(le_u32, |v| v as usize), num_tables as usize)
                .parse(remainder)?;

        let mut num_rows_per_present_table =
            num_rows_per_present_table.into_iter();

        // `num_rows_per_present_table` contains an entry per each table
        // that is present. But we need an array with an entry per table,
        // no matter if it's present or not. Of course, tables that are not
        // present will have zero rows.
        self.num_rows = Vec::with_capacity(64);

        for i in 0..64 {
            if valid & (1 << i) != 0 {
                self.num_rows.push(num_rows_per_present_table.next().unwrap());
            } else {
                self.num_rows.push(0)
            }
        }

        self.string_index_size =
            if heap_sizes & 1 != 0 { IndexSize::U32 } else { IndexSize::U16 };

        self.guid_index_size =
            if heap_sizes & 2 != 0 { IndexSize::U32 } else { IndexSize::U16 };

        self.blob_index_size =
            if heap_sizes & 4 != 0 { IndexSize::U32 } else { IndexSize::U16 };

        // Parse the tables, which are one after the other. Some tables are
        // not interesting, but we need to parse them anyways because they
        // have a variable length, and we can't skip them without some amount
        // of parsing.

        (remainder, self.modules) = self
            .parse_table(self.parse_module_row(), Table::Module)(
            remainder
        )?;

        (remainder, self.type_refs) = self
            .parse_table(self.parse_type_ref_row(), Table::TypeRef)(
            remainder,
        )?;

        (remainder, self.type_defs) = self
            .parse_table(self.parse_type_def_row(), Table::TypeDef)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.table_index(Table::Field), Table::FieldPtr)(
            remainder,
        )?;

        (remainder, _) =
            self.skip_table(self.parse_field_row(), Table::Field)(remainder)?;

        (remainder, _) = self.skip_table(
            self.table_index(Table::MethodDef),
            Table::MethodDefPtr,
        )(remainder)?;

        (remainder, self.method_defs) = self
            .parse_table(self.parse_method_def_row(), Table::MethodDef)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.table_index(Table::Param), Table::ParamPtr)(
            remainder,
        )?;

        (remainder, self.params) =
            self.parse_table(self.parse_param_row(), Table::Param)(remainder)?;

        (remainder, self.interface_impls) = self.parse_table(
            self.parse_interface_impl_row(),
            Table::InterfaceImpl,
        )(remainder)?;

        (remainder, self.member_refs) = self
            .parse_table(self.parse_member_ref_row(), Table::MemberRef)(
            remainder,
        )?;

        (remainder, self.constants) = self
            .parse_table(self.parse_constant_row(), Table::Constant)(
            remainder,
        )?;

        (remainder, self.custom_attributes) = self.parse_table(
            self.parse_custom_attribute_row(),
            Table::CustomAttribute,
        )(remainder)?;

        (remainder, _) = self
            .skip_table(self.parse_field_marshal_row(), Table::FieldMarshal)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.parse_decl_security_row(), Table::DeclSecurity)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.parse_class_layout_row(), Table::ClassLayout)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.parse_field_layout_row(), Table::FieldLayout)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.blob_index(), Table::StandaloneSig)(
            remainder
        )?;

        (remainder, _) = self
            .skip_table(self.parse_event_map_row(), Table::EventMap)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.table_index(Table::Event), Table::EventPtr)(
            remainder,
        )?;

        (remainder, _) =
            self.skip_table(self.parse_event_row(), Table::Event)(remainder)?;

        (remainder, _) = self
            .skip_table(self.parse_property_map_row(), Table::PropertyMap)(
            remainder,
        )?;

        (remainder, _) = self.skip_table(
            self.table_index(Table::Property),
            Table::PropertyPtr,
        )(remainder)?;

        (remainder, _) = self
            .skip_table(self.parse_property_row(), Table::Property)(
            remainder,
        )?;

        (remainder, _) = self.skip_table(
            self.parse_method_semantics_row(),
            Table::MethodSemantics,
        )(remainder)?;

        (remainder, _) = self
            .skip_table(self.parse_method_impl_row(), Table::MethodImpl)(
            remainder,
        )?;

        (remainder, self.module_refs) = self.parse_table(
            map(self.string_index(), |index| self.get_string(index)),
            Table::ModuleRef,
        )(remainder)?;

        (remainder, self.type_specs) =
            self.parse_table(self.blob_index(), Table::TypeSpec)(remainder)?;

        (remainder, _) = self
            .skip_table(self.parse_impl_map_row(), Table::ImplMap)(
            remainder
        )?;

        (remainder, self.field_rvas) = self
            .parse_table(self.parse_field_rva_row(), Table::FieldRva)(
            remainder,
        )?;

        (remainder, _) =
            self.skip_table(take(8_usize), Table::EncLog)(remainder)?;

        (remainder, _) =
            self.skip_table(take(4_usize), Table::EncMap)(remainder)?;

        (remainder, self.assemblies) = self
            .parse_table(self.parse_assembly_row(), Table::Assembly)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(take(4_usize), Table::AssemblyProcessor)(
            remainder
        )?;

        (remainder, _) =
            self.skip_table(take(12_usize), Table::AssemblyOs)(remainder)?;

        (remainder, self.assembly_refs) = self
            .parse_table(self.parse_assembly_ref_row(), Table::AssemblyRef)(
            remainder,
        )?;

        (remainder, _) = self.skip_table(
            self.parse_assembly_ref_processor_row(),
            Table::AssemblyRefProcessor,
        )(remainder)?;

        (remainder, _) = self.skip_table(
            self.parse_assembly_ref_os_row(),
            Table::AssemblyRefOs,
        )(remainder)?;

        (remainder, _) =
            self.skip_table(self.parse_file_row(), Table::File)(remainder)?;

        (remainder, _) = self
            .skip_table(self.parse_exported_type_row(), Table::ExportedType)(
            remainder,
        )?;

        (remainder, self.resources) = self.parse_table(
            self.parse_manifest_resource_row(),
            Table::ManifestResource,
        )(remainder)?;

        (remainder, self.nested_classes) = self
            .parse_table(self.parse_nested_class_row(), Table::NestedClass)(
            remainder,
        )?;

        (remainder, self.generic_params) = self
            .parse_table(self.parse_generic_param_row(), Table::GenericParam)(
            remainder,
        )?;

        (remainder, _) = self
            .skip_table(self.parse_method_spec_row(), Table::MethodSpec)(
            remainder,
        )?;

        (remainder, _) = self.skip_table(
            self.parse_generic_param_constraint_row(),
            Table::GenericParamConstraint,
        )(remainder)?;

        Ok((remainder, ()))
    }

    /// Parses the rows of `table` using `row_parser`.
    ///
    /// To prevent excessive memory usage or long parsing times on large or
    /// corrupted files, at most [`Self::MAX_ROWS_PER_TABLE`] rows are parsed
    /// and returned. However, `self.num_rows` preserves the actual number of
    /// rows declared in the `#~` header so that:
    ///
    /// 1. Table and coded index sizes (16-bit vs 32-bit) are computed
    ///    correctly according to ECMA-335 II.24.2.6.
    /// 2. Any remaining rows beyond [`Self::MAX_ROWS_PER_TABLE`] can be
    ///    skipped in the input slice, keeping subsequent tables in the `#~`
    ///    stream properly aligned.
    fn parse_table<'b, O, P>(
        &'b self,
        mut row_parser: P,
        table: Table,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Vec<O>> + 'b
    where
        P: Parser<&'a [u8], Output = O, Error = NomError<'a>> + 'b,
    {
        move |input: &'a [u8]| {
            let num_rows = self.num_rows(table);
            let rows_to_parse = min(num_rows, Self::MAX_ROWS_PER_TABLE);

            let (remainder, rows) =
                count(|i| row_parser.parse(i), rows_to_parse).parse(input)?;

            // All rows in a given metadata table have the exact same byte
            // size. If the table has more than `MAX_ROWS_PER_TABLE` rows,
            // compute the row size from the `MAX_ROWS_PER_TABLE` rows just
            // parsed and skip the remaining rows so the next table starts at
            // the right offset.
            let remainder = if let Some(extra_rows) =
                num_rows.checked_sub(Self::MAX_ROWS_PER_TABLE)
                && extra_rows > 0
            {
                let row_size =
                    (input.len() - remainder.len()) / Self::MAX_ROWS_PER_TABLE;
                let bytes_to_skip = extra_rows.saturating_mul(row_size);
                let (remainder, _) = take(bytes_to_skip)(remainder)?;
                remainder
            } else {
                remainder
            };

            Ok((remainder, rows))
        }
    }

    /// Like [`Self::parse_table`], but discards parsed rows without allocating
    /// a [`Vec`].
    fn skip_table<'b, O, P>(
        &'b self,
        mut row_parser: P,
        table: Table,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + 'b
    where
        P: Parser<&'a [u8], Output = O, Error = NomError<'a>> + 'b,
    {
        move |input: &'a [u8]| {
            let num_rows = self.num_rows(table);
            let rows_to_parse = min(num_rows, Self::MAX_ROWS_PER_TABLE);

            let mut remainder = input;
            for _ in 0..rows_to_parse {
                (remainder, _) = row_parser.parse(remainder)?;
            }

            let remainder = if let Some(extra_rows) =
                num_rows.checked_sub(Self::MAX_ROWS_PER_TABLE)
                && extra_rows > 0
            {
                let row_size =
                    (input.len() - remainder.len()) / Self::MAX_ROWS_PER_TABLE;
                let bytes_to_skip = extra_rows.saturating_mul(row_size);
                let (remainder, _) = take(bytes_to_skip)(remainder)?;
                remainder
            } else {
                remainder
            };

            Ok((remainder, ()))
        }
    }

    /// Parses the `#US` stream, and returns all the string contained
    /// in it.
    fn parse_user_strings(&self) -> Vec<&'a [u8]> {
        let strings = if let Some(us_stream) =
            self.us_stream.and_then(|index| self.get_stream(index))
        {
            // The `#US` stream is composed of a series of varints followed by
            // the number of bytes indicated by the varint.
            many0(length_data(var_uint))
                .parse(us_stream)
                .map(|(_, strings)| strings)
                .ok()
        } else {
            None
        };

        let mut strings = match strings {
            Some(strings) => strings,
            None => return vec![],
        };

        // Retain only the strings with length >= 3. All non-empty strings have
        // at least 3 bytes because strings are UTF-16 (2 bytes per character)
        // plus an extra byte that can be 0x00 or 0x01, and indicates whether
        // any of the UTF-16 characters have a non-zero bit in the top byte.
        // This is described in ECMA-335 II.24.2.4.
        strings.retain(|s| s.len() >= 3);

        // Discard the extra byte from all strings.
        for string in strings.iter_mut() {
            *string = &string[0..string.len() - 1];
        }

        strings
    }

    /// Try to find a custom attribute named `GuidAttribute` and return the
    /// string associated it.
    fn parse_typelib(&self) -> Option<&'a str> {
        // Find the `GuidAttribute`.
        let guid_attribute = self.custom_attributes.iter().find(|attr| {
            if attr.parent.table == Table::Assembly
                && attr.type_.table == Table::MemberRef
            {
                return self
                    .get_member_ref(&attr.type_)
                    .and_then(|m_ref| self.get_type_ref(&m_ref.class))
                    .map(|class| matches!(class.name, Some("GuidAttribute")))
                    .unwrap_or(false);
            }
            false
        });

        guid_attribute
            .and_then(|guid_attribute| guid_attribute.value)
            .and_then(|value_blob| {
                let (_, (_prolog, name)) = (
                    le_u16::<&[u8], nom::error::Error<&'a [u8]>>, // prolog
                    map_res(length_data(u8), from_utf8), // string size followed by string
                )
                    .parse(value_blob)
                    .ok()?;
                Some(name)
            })
    }

    fn parse_user_types(&self) -> Vec<Class<'a>> {
        self.iter_user_types().collect()
    }

    fn iter_user_types(&self) -> impl Iterator<Item = Class<'a>> + '_ {
        let mut highest_method_list = 0;
        let mut remaining_sig_bytes = Self::MAX_METHOD_SIG_BYTES;

        self.type_defs.iter().enumerate().filter_map(move |(idx, type_def)| {
            // Skip type definitions with invalid (empty) names, and the
            // "<Module>" pseudo-class.
            if type_def.name.is_none_or(|name| name == "<Module>") {
                return None;
            }

            let generic_class_params: Vec<_> = self
                .generic_params
                .iter()
                .filter_map(|param| {
                    if param.owner.table == Table::TypeDef
                        && param.owner.index == idx
                    {
                        param.name
                    } else {
                        None
                    }
                })
                .collect();

            // The methods belonging to this type in the MethodDef table go
            // from the index specified by `method_list` to the index specified
            // by the next type's `method_list`. If this is the last type, then
            // it goes to the end of the MethodDef table.
            //
            // According to ECMA-335 II.22.37, `method_list` should be
            // monotonically non-decreasing across the TypeDef table, with
            // types that have no methods repeating the `method_list` of the
            // following type. However, some tools (such as Unity/IL2CPP
            // linkers and dumpers) set `method_list` to 1 (0-based 0) for
            // every type that has no methods. One example of this is file:
            // ef1c257f1dc7e21a0df2221965c42f72a4097010e1f8be00018866acdaf088ec
            //
            // If `type_def.method_list` is less than `highest_method_list`,
            // it is out of order (e.g. reset to 0) and the type has no
            // methods. Otherwise, we look for the next type with a
            // `method_list >= type_def.method_list` so that intermediate
            // types with `method_list == 0` do not truncate the current
            // type's method list or cause methods from index 0 to be
            // repeatedly re-assigned to multiple types.
            let method_defs = if type_def.method_list >= highest_method_list {
                if let Some(next_type_def) = self.type_defs[idx + 1..]
                    .iter()
                    .find(|t| t.method_list >= type_def.method_list)
                {
                    highest_method_list = next_type_def.method_list;
                    self.method_defs
                        .get(type_def.method_list..next_type_def.method_list)
                } else {
                    highest_method_list = usize::MAX;
                    self.method_defs.get(type_def.method_list..)
                }
            } else {
                None
            };

            let methods = if let Some(method_defs) = method_defs {
                let mut methods = Vec::with_capacity(method_defs.len());
                for (m_idx, method_def) in method_defs.iter().enumerate() {
                    if let Some(m) = self.convert_method_def(
                        type_def.method_list + m_idx,
                        method_def,
                        generic_class_params.as_slice(),
                        &mut remaining_sig_bytes,
                    ) {
                        methods.push(m);
                    }
                }
                methods
            } else {
                vec![]
            };

            // `base_types` will contain the names of the classes the current
            // class inherits from.
            let mut base_types = Vec::new();
            let mut depth = 0;

            // If the current class extends some other class, add the full name
            // of this other class to `base_types`.
            if let Some(name) = self.type_def_or_ref_fullname(
                &type_def.extends,
                &mut depth,
                generic_class_params.as_slice(),
                &[],
            ) {
                base_types.push(name)
            }

            // For every interface implemented by the current class, add its
            // full name to `base_types`.
            base_types.extend(self.interface_impls.iter().filter_map(
                |interface_impl| {
                    if interface_impl.class == idx {
                        depth = 0;
                        self.type_def_or_ref_fullname(
                            &interface_impl.interface,
                            &mut depth,
                            generic_class_params.as_slice(),
                            &[],
                        )
                    } else {
                        None
                    }
                },
            ));

            Some(Class {
                full_name: self.type_full_name(idx),
                base_types,
                visibility: type_def.visibility(),
                semantics: type_def.class_semantics(),
                is_abstract: type_def.is_abstract(),
                is_sealed: type_def.is_sealed(),
                methods,
                generic_params: generic_class_params,
            })
        })
    }

    fn convert_method_def(
        &self,
        method_def_idx: usize,
        method_def: &MethodDef<'a>,
        generic_class_params: &[&'a str],
        remaining_sig_bytes: &mut usize,
    ) -> Option<Method<'a>> {
        if *remaining_sig_bytes == 0 {
            return None;
        }

        let method_name = method_def.name?;

        let (remainder, flags) =
            u8::<&[u8], nom::error::Error<&'a [u8]>>(method_def.signature?)
                .ok()?;

        let (remainder, (_generic_param_count, param_count)) = (
            // Generic param count, present only if
            // SIG_FLAG_GENERIC flag is set.
            cond(flags & 0x10 != 0, var_uint),
            // Regular param count.
            verify(var_uint, |count| *count < Self::MAX_PARAMS),
        )
            .parse(remainder)
            .ok()?;

        let generic_method_params: Vec<_> = self
            .generic_params
            .iter()
            .filter_map(|param| {
                if param.owner.table == Table::MethodDef
                    && param.owner.index == method_def_idx
                {
                    param.name
                } else {
                    None
                }
            })
            .collect();

        let mut return_type = BoundedString::new(Self::MAX_TYPE_NAME_LEN);
        let mut depth = 0;

        let res = self.parse_type_spec(
            remainder,
            &mut return_type,
            &mut depth,
            generic_class_params,
            generic_method_params.as_slice(),
        );

        let prev_budget = *remaining_sig_bytes;

        *remaining_sig_bytes = prev_budget.saturating_sub(return_type.len());

        if return_type.len() > prev_budget {
            return None;
        }

        let mut remainder = res.ok()?;

        // Return type for constructors is always set to None, which YARA sees
        // as undefined, for FileInfo compatibility.
        let return_type = if matches!(method_name, ".ctor" | ".cctor") {
            None
        } else {
            Some(return_type.into_inner())
        };

        let mut method_params =
            Vec::with_capacity(min(param_count as usize, remainder.len()));

        for i in 0..param_count {
            if *remaining_sig_bytes == 0 {
                return None;
            }

            // Try to find the param in the Param table. Params for the current
            // method start at the index indicated by `method_def.param_list`.
            // If found, and the Param struct has a name, use it. If not found,
            // or the Param struct doesn't have a name use P_xx, where xx is the
            // argument number.
            let name = self
                .params
                .get(method_def.param_list.saturating_add(i as usize))
                .and_then(|param| param.name)
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Cow::Owned(format!("P_{i}")));

            let mut param_type = BoundedString::new(Self::MAX_TYPE_NAME_LEN);

            let res = self.parse_type_spec(
                remainder,
                &mut param_type,
                &mut depth,
                generic_class_params,
                generic_method_params.as_slice(),
            );

            let cost =
                Self::PARAM_OVERHEAD_BYTES.saturating_add(param_type.len());

            let prev_budget = *remaining_sig_bytes;

            *remaining_sig_bytes = prev_budget.saturating_sub(cost);

            if cost > prev_budget {
                return None;
            }
            remainder = res.ok()?;

            method_params.push(MethodParam {
                name,
                type_: Some(param_type.into_inner()),
            })
        }

        Some(Method {
            name: method_name,
            generic_params: generic_method_params,
            params: method_params,
            return_type,
            visibility: method_def.visibility(),
            is_final: method_def.is_final(),
            is_abstract: method_def.is_abstract(),
            is_virtual: method_def.is_virtual(),
            is_static: method_def.is_static(),
        })
    }

    /// Given an index into the TypeDef table, writes its full name into
    /// `output`.
    ///
    /// When the type is not nested the full name is simply `namespace.name`,
    /// when the type is a nested one, the full name includes the name of
    /// its parent type as well.
    fn write_type_full_name(
        &self,
        type_def_idx: usize,
        output: &mut BoundedString,
    ) -> Result<(), Error<'a>> {
        let first_type_def =
            self.type_defs.get(type_def_idx).ok_or(Error::InvalidType)?;
        if !first_type_def.is_nested() {
            let name =
                first_type_def.plain_name().ok_or(Error::InvalidType)?;
            if let Some(namespace) = first_type_def.namespace {
                output.reserve(
                    namespace
                        .len()
                        .saturating_add(1)
                        .saturating_add(name.len()),
                )?;
                output.push_str(namespace)?;
                output.push('.')?;
                output.push_str(name)?;
            } else {
                output.push_str(name)?;
            }
            return Ok(());
        }

        let mut next_idx = Some(type_def_idx);
        let mut parts = [""; Self::MAX_RECURSION];
        let mut len = 0;

        while let Some(idx) = next_idx.take() {
            let type_def =
                self.type_defs.get(idx).ok_or(Error::InvalidType)?;

            // Protect against corrupted files.
            if len >= Self::MAX_RECURSION {
                return Err(Error::RecursionLimit);
            }

            parts[len] = type_def.plain_name().ok_or(Error::InvalidType)?;
            len += 1;

            if let Some(namespace) = type_def.namespace {
                if len < Self::MAX_RECURSION {
                    parts[len] = namespace;
                }
                len += 1;
            }

            // If the type is a nested one, an entry in `nested_classes` must
            // exist where `nested_class` is the index of the current type
            // and `enclosing_class` is the index of the parent type. Both
            // are indexes into the `type_defs` table. `next_idx` will
            // contain the index of the parent type. In normal files
            // `enclosing_class` is different from `nested_class` because
            // types can not be nested inside themselves, but we need to check
            // for that case because this can happen in corrupted files.
            if type_def.is_nested() {
                next_idx = self
                    .nested_classes
                    .iter()
                    .find(|c| {
                        c.nested_class == idx && c.enclosing_class != idx
                    })
                    .map(|c| c.enclosing_class);
            }
        }

        let valid_len = min(len, Self::MAX_RECURSION);
        let total_bytes = parts[..valid_len]
            .iter()
            .fold(0usize, |acc, s| acc.saturating_add(s.len()))
            .saturating_add(valid_len.saturating_sub(1));
        output.reserve(total_bytes)?;

        // The innermost type is pushed first into the list, but it should be
        // the last one in the resulting name. So the list must be iterated
        // backwards.
        for (i, part) in parts[..valid_len].iter().rev().enumerate() {
            if i > 0 {
                output.push('.')?;
            }
            output.push_str(part)?;
        }

        Ok(())
    }

    fn type_full_name(&self, type_def_idx: usize) -> Option<String> {
        let mut output = BoundedString::new(Self::MAX_TYPE_NAME_LEN);
        self.write_type_full_name(type_def_idx, &mut output).ok()?;
        Some(output.into_inner())
    }

    /// Given a [`CodedIndex`] that can point either to the TypeDef, TypeRef or
    /// TypeSpec tables, writes a string that describes the type into `output`.
    fn write_type_def_or_ref_fullname(
        &self,
        index: &CodedIndex,
        output: &mut BoundedString,
        depth: &mut usize,
        generic_class_params: &[&'a str],
        generic_method_params: &[&'a str],
    ) -> Result<(), Error<'a>> {
        match index.table {
            Table::TypeDef => self.write_type_full_name(index.index, output),
            Table::TypeRef => {
                let t = self.get_type_ref(index).ok_or(Error::InvalidType)?;
                let name = t.plain_name().ok_or(Error::InvalidType)?;
                if let Some(namespace) = t.namespace {
                    output.reserve(
                        namespace
                            .len()
                            .saturating_add(1)
                            .saturating_add(name.len()),
                    )?;
                    output.push_str(namespace)?;
                    output.push('.')?;
                    output.push_str(name)?;
                } else {
                    output.push_str(name)?;
                }
                Ok(())
            }
            Table::TypeSpec => {
                let blob_index =
                    self.get_type_spec(index).ok_or(Error::InvalidType)?;
                let data =
                    self.get_blob(*blob_index).ok_or(Error::InvalidType)?;
                self.parse_type_spec(
                    data,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    fn type_def_or_ref_fullname(
        &self,
        index: &CodedIndex,
        depth: &mut usize,
        generic_class_params: &[&'a str],
        generic_method_params: &[&'a str],
    ) -> Option<String> {
        let mut output = BoundedString::new(Self::MAX_TYPE_NAME_LEN);
        self.write_type_def_or_ref_fullname(
            index,
            &mut output,
            depth,
            generic_class_params,
            generic_method_params,
        )
        .ok()?;
        Some(output.into_inner())
    }

    /// Parses a type spec blob, writing a textual representation of the
    /// type into the `output` string.
    ///
    /// This function can call itself recursively, and the `depth` argument
    /// serves the purpose of controlling the recursion depth. It is a
    /// reference to a `usize` that gets incremented when entering a recursive
    /// call. Initially `depth` must be zero.
    ///
    /// ECMA-335 Section II.23.2.12
    fn parse_type_spec(
        &self,
        input: &'a [u8],
        output: &mut BoundedString,
        depth: &mut usize,
        generic_class_params: &[&'a str],
        generic_method_params: &[&'a str],
    ) -> Result<&'a [u8], Error<'a>> {
        if *depth == Self::MAX_RECURSION {
            return Err(Error::RecursionLimit);
        }

        if output.is_full() {
            return Err(Error::OutputWrite(std::fmt::Error));
        }

        let (mut remainder, type_) =
            map_opt(u8, num_traits::FromPrimitive::from_u8).parse(input)?;

        *depth += 1;

        match type_ {
            Type::Void => output.push_str("void")?,
            Type::Bool => output.push_str("bool")?,
            Type::Char => output.push_str("char")?,
            Type::I1 => output.push_str("sbyte")?,
            Type::U1 => output.push_str("byte")?,
            Type::I2 => output.push_str("short")?,
            Type::U2 => output.push_str("ushort")?,
            Type::I4 => output.push_str("int")?,
            Type::U4 => output.push_str("uint")?,
            Type::I8 => output.push_str("long")?,
            Type::U8 => output.push_str("ulong")?,
            Type::R4 => output.push_str("float")?,
            Type::R8 => output.push_str("double")?,
            Type::Object => output.push_str("object")?,
            Type::String => output.push_str("string")?,
            Type::TypedRef => output.push_str("TypedReference")?,
            Type::I => output.push_str("IntPtr")?,
            Type::U => output.push_str("UintPtr")?,
            Type::Ptr => {
                output.push_str("Ptr<")?;
                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
                output.push('>')?;
            }
            Type::ByRef => {
                output.push_str("ref ")?;
                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
            }
            Type::ValueType | Type::Class => {
                let coded_index;

                (remainder, coded_index) = map_res(var_uint, |v| {
                    CodedIndex::from_u32(Table::TYPE_DEF_OR_REF, v)
                })
                .parse(remainder)?;

                self.write_type_def_or_ref_fullname(
                    &coded_index,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
            }
            Type::Var | Type::MVar => {
                let index;

                (remainder, index) = var_uint(remainder)?;

                let name = if matches!(type_, Type::Var) {
                    generic_class_params
                        .get(index as usize)
                        .ok_or(Error::InvalidType)?
                } else {
                    generic_method_params
                        .get(index as usize)
                        .ok_or(Error::InvalidType)?
                };

                output.push_str(name)?;
            }
            Type::Array => {
                let dimensions;
                let sizes;
                let lower_bounds;

                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;

                (remainder, (dimensions, sizes, lower_bounds)) = (
                    // dimensions, limited to a sane limit of
                    // MAX_ARRAY_DIMENSION as a protection against corrupted
                    // files.
                    verify(var_uint, |dimension| {
                        *dimension <= Self::MAX_ARRAY_DIMENSION
                    }),
                    // number of sizes, followed by the sizes as variable
                    // length unsigned ints. The number of sizes is also limited
                    // to MAX_ARRAY_DIMENSION.
                    length_count(
                        verify(var_uint, |n| *n <= Self::MAX_ARRAY_DIMENSION),
                        var_uint,
                    ),
                    // number of lower bounds, followed by the lower bounds as
                    // variable length *signed* ints. This is the only place
                    // where signed ints are used.
                    length_count(
                        verify(var_uint, |n| *n <= Self::MAX_ARRAY_DIMENSION),
                        var_sint,
                    ),
                )
                    .parse(remainder)?;

                write!(output, "[")?;
                for i in 0..dimensions {
                    let i = i as usize;
                    let size = sizes.get(i).cloned().map(|s| s as i32);
                    let lower_bound = lower_bounds.get(i).cloned();

                    match (lower_bound, size) {
                        (Some(0), Some(size)) => {
                            write!(output, "{size}")?;
                        }
                        (Some(l), Some(size)) if size >= 1 => {
                            write!(output, "{}...{}", l, l + size - 1)?;
                        }
                        (Some(l), None) => {
                            write!(output, "{l}...")?;
                        }
                        (None, Some(size)) => {
                            write!(output, "{size}")?;
                        }
                        _ => {}
                    }

                    // If not the last item, prepend a comma.
                    if i + 1 != dimensions as usize {
                        write!(output, ",")?;
                    }
                }
                write!(output, "]")?;
            }
            Type::SzArray => {
                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
                write!(output, "[]")?;
            }
            Type::GenericInst => {
                let count;

                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;

                (remainder, count) =
                    verify(var_uint, |count| *count < Self::MAX_PARAMS)
                        .parse(remainder)?;

                write!(output, "<")?;
                for i in 1..=count {
                    remainder = self.parse_type_spec(
                        remainder,
                        output,
                        depth,
                        generic_class_params,
                        generic_method_params,
                    )?;
                    if i < count {
                        write!(output, ",")?;
                    }
                }
                write!(output, ">")?;
            }
            Type::FnPtr => {
                let count;

                // Skip flags and read param count. Param count is limited
                // to MAX_PARAMS.
                (remainder, (_, count)) =
                    (u8, verify(var_uint, |count| *count < Self::MAX_PARAMS))
                        .parse(remainder)?;

                write!(output, "FnPtr<")?;
                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
                write!(output, "(")?;
                for i in 1..=count {
                    remainder = self.parse_type_spec(
                        remainder,
                        output,
                        depth,
                        generic_class_params,
                        generic_method_params,
                    )?;
                    if i < count {
                        write!(output, ", ")?;
                    }
                }
                write!(output, ")>")?;
            }
            Type::CModReqd | Type::CModOpt => {
                (remainder, _) = var_uint(remainder)?;
                remainder = self.parse_type_spec(
                    remainder,
                    output,
                    depth,
                    generic_class_params,
                    generic_method_params,
                )?;
            }
            _ => return Err(Error::InvalidType),
        };

        *depth -= 1;

        Ok(remainder)
    }

    /// Returns a parser for an index of the given size. Index sizes can be
    /// 16-bits or 32-bits. The result is always returned as `u32`.
    fn index(
        &self,
        size: IndexSize,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], u32> {
        move |input: &[u8]| match size {
            IndexSize::U16 => {
                let (remainder, i) = le_u16(input)?;
                Ok((remainder, i as u32))
            }
            IndexSize::U32 => le_u32(input),
        }
    }

    /// Returns a parser for an index in the `#Strings` stream.
    #[inline]
    fn string_index(
        &self,
    ) -> impl Parser<&'a [u8], Output = StringIndex, Error = NomError<'a>>
    {
        map(self.index(self.string_index_size), StringIndex)
    }

    /// Returns a parser for an index in the `#GUID` stream.
    #[inline]
    fn guid_index(
        &self,
    ) -> impl Parser<&'a [u8], Output = GuidIndex, Error = NomError<'a>> {
        map(self.index(self.guid_index_size), GuidIndex)
    }

    /// Returns a parser for an index in the `#Blob` stream.
    #[inline]
    fn blob_index(
        &self,
    ) -> impl Parser<&'a [u8], Output = BlobIndex, Error = NomError<'a>> {
        map(self.index(self.blob_index_size), BlobIndex)
    }

    /// Returns a parser for an index in the given table.
    #[inline]
    fn table_index(
        &self,
        table: Table,
    ) -> impl Parser<&'a [u8], Output = usize, Error = NomError<'a>> + '_ {
        move |input: &'a [u8]| {
            let (remainder, index) =
                self.index(if self.num_rows[table as usize] > 65535 {
                    IndexSize::U32
                } else {
                    IndexSize::U16
                })(input)?;

            // Table indexes in are 1-based, but here we make them 0-based,
            // so that we can use them as Rust vector indexes.
            let index = index.saturating_sub(1) as usize;

            Ok((remainder, index))
        }
    }

    /// A coded index points to one of multiple possible tables. These indexes
    /// contain both the index itself and information about the table the index
    /// refers to.
    ///
    /// Coded indexes are encoded as `(index << tag_size | tag)`. The lowest
    /// `tag_size` bits contain a tag number that indicates the table being
    /// indexed, while the highest bits contain the index itself.
    ///
    /// `tag_size` depends on the number of tables the index can refer to. For
    /// instance, for distinguishing between two tables we only need two
    /// possible tags (0 and 1), therefore 1 bit is enough and `tag_size` is 1.
    /// For three or four tables we need two bits, and `tag_size` is 2. In
    /// general `tag_size = ceil(log2(n))` where `n` is the number of tables.
    ///
    /// Also, the overall size of a coded index can be 16 or 32 bits, depending
    /// on the sizes of the tables it refers to. The maximum index number that
    /// can fit in an 16 bits coded index is `2^(16 - tag_size)` (remember, some
    /// bits are used for encoding the table), so if the largest table has less
    /// than `2^(16 - tag_size)` elements, the coded index is 16 bits. Otherwise,
    /// it will be 32 bits long.
    fn coded_index<'s>(
        &'s self,
        tables: &'s [Table],
    ) -> impl Parser<&'a [u8], Output = CodedIndex, Error = NomError<'a>> + 's
    {
        let num_rows_per_table = tables.iter().map(|table| {
            self.num_rows.get(*table as usize).cloned().unwrap_or_default()
        });
        // The maximum number of tables that can be combined in a coded
        // index is 22, corresponding to the HasCustomAttribute coded
        // index.
        // See: ECMA-335 Section II.24.2.6 where the `#~` stream is
        // described.
        assert!(num_rows_per_table.len() <= 22);

        // Compute the size of the largest table.
        let max_table_size = num_rows_per_table.max().unwrap();

        // If the maximum number of rows of tables t1, t2 .. tN is less
        // than 2^(16 - tag_size), the index is 2 bytes, and 4 bytes if
        // otherwise. That's because `tag_size` bits in the coded index
        // are used for storing a tag number that indicates the target
        // table, while the remaining bits are used for storing the index
        // itself. So, the maximum index that can be represented with 16
        // bits is 2^(16 - tag_size), if the maximum number of rows is
        // larger than that we need 4 bytes.
        let tag_size = f64::log2(tables.len() as f64).ceil() as u32;
        let threshold = 1u64.checked_shl(16 - tag_size).unwrap();

        let index_size = if (max_table_size as u64) <= threshold {
            IndexSize::U16
        } else {
            IndexSize::U32
        };

        move |input: &'a [u8]| {
            map_res(self.index(index_size), |v| {
                CodedIndex::from_u32(tables, v)
            })
            .parse(input)
        }
    }

    /// Parse Module row.
    ///
    /// ECMA-335 Section II.22.30
    fn parse_module_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = Option<&'a str>, Error = NomError<'a>> + '_
    {
        map(
            (
                // generation (reserved, shall be zero).
                le_u16,
                // name (index into the `#String` heap)
                map(self.string_index(), |index| self.get_string(index)),
                // mvid (index into the `#GUID` heap)
                self.guid_index(),
                // enc_id (index into the `#GUID` heap)
                self.guid_index(),
                // enc_base_id (index into the `#GUID` heap)
                self.guid_index(),
            ),
            |(_, name, _, _, _)| name,
        )
    }

    /// Parse TypeRef row.
    ///
    /// ECMA-335 Section II.22.38
    fn parse_type_ref_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = TypeRef<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                // resolution scope
                self.coded_index(&[
                    Table::Module,
                    Table::ModuleRef,
                    Table::AssemblyRef,
                    Table::TypeRef,
                ]),
                // type name
                map(self.string_index(), |index| self.get_string(index)),
                // type namespace
                map(self.string_index(), |index| self.get_string(index)),
            ),
            |(_resolution_scope, type_name, type_namespace)| TypeRef {
                name: type_name,
                namespace: type_namespace,
            },
        )
    }

    /// Parse TypeDef row.
    ///
    /// ECMA-335 Section II.22.37.
    fn parse_type_def_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = TypeDef<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                // flags
                le_u32,
                // type name (index into the `#String` heap)
                map(self.string_index(), |index| self.get_string(index)),
                // type namespace (index into the `#String` heap)
                map(self.string_index(), |index| self.get_string(index)),
                // extends
                self.coded_index(Table::TYPE_DEF_OR_REF),
                // field list
                self.table_index(Table::Field),
                // method list
                self.table_index(Table::MethodDef),
            ),
            |(flags, name, namespace, extends, _field_list, method_list)| {
                TypeDef {
                    flags,
                    name: name.filter(|&v| !v.is_empty()),
                    // The namespace can be an empty string (""),
                    namespace: namespace.filter(|&v| !v.is_empty()),
                    method_list,
                    extends,
                }
            },
        )
    }

    /// Parse Field row.
    ///
    /// ECMA-335 Section II.22.15.
    fn parse_field_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                // flags
                le_u16,
                // name (index into the `#String` heap)
                self.string_index(),
                // signature (index into the `#Blob` heap)
                self.blob_index(),
            ),
            |_| (),
        )
    }

    /// Parse MethodDef row.
    ///
    /// ECMA-335 Section II.22.26.
    fn parse_method_def_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = MethodDef<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                // rva
                le_u32,
                // impl_flags
                le_u16,
                // flags
                le_u16,
                // name (index into the `#String` heap)
                map(self.string_index(), |index| self.get_string(index)),
                // signature (index into the `#Blob` heap)
                map(self.blob_index(), |index| self.get_blob(index)),
                // param_list (index into the param table)
                self.table_index(Table::Param),
            ),
            |(_, _, flags, name, signature, param_list)| MethodDef {
                flags,
                name,
                signature,
                param_list,
            },
        )
    }

    /// Parse Param row.
    ///
    /// ECMA-335 Section II.22.33.
    fn parse_param_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = Param<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                le_u16, // flags
                le_u16, // sequence
                // name
                map(self.string_index(), |index| self.get_string(index)),
            ),
            |(_flags, _sequence, name)| Param { name },
        )
    }

    /// Parse InterfaceImpl row.
    ///
    /// ECMA-335 Section II.22.23.
    fn parse_interface_impl_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = InterfaceImpl, Error = NomError<'a>> + '_
    {
        map(
            (
                self.table_index(Table::TypeDef), // class
                self.coded_index(Table::TYPE_DEF_OR_REF), // interface
            ),
            |(class, interface)| InterfaceImpl { class, interface },
        )
    }

    /// Parse MemberRef row.
    ///
    /// ECMA-335 Section II.22.25.
    fn parse_member_ref_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = MemberRef, Error = NomError<'a>> + '_
    {
        map(
            (
                // class
                self.coded_index(&[
                    Table::TypeDef,
                    Table::TypeRef,
                    Table::ModuleRef,
                    Table::MethodDef,
                    Table::TypeSpec,
                ]),
                // name
                self.string_index(),
                // signature
                self.blob_index(),
            ),
            |(class, _name, _signature)| MemberRef { class },
        )
    }

    /// Parse Constant row.
    ///
    /// ECMA-335 Section II.22.9.
    fn parse_constant_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = Constant<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                map_opt(u8, num_traits::FromPrimitive::from_u8), // type
                u8,                                              // padding
                self.coded_index(&[
                    Table::Field,
                    Table::Param,
                    Table::Property,
                ]),
                map(self.blob_index(), |index| self.get_blob(index)), // value
            ),
            |(type_, _, _, value)| Constant { type_, value },
        )
    }

    /// Parse CustomAttribute row.
    ///
    /// ECMA-335 Section II.22.10.
    fn parse_custom_attribute_row(
        &self,
    ) -> impl Parser<
        &'a [u8],
        Output = CustomAttribute<'a>,
        Error = NomError<'a>,
    > + '_ {
        map(
            (
                // parent
                self.coded_index(Table::HAS_CUSTOM_ATTRIBUTE),
                // type
                self.coded_index(Table::CUSTOM_ATTRIBUTE_TYPE),
                // value
                map(self.blob_index(), |index| self.get_blob(index)),
            ),
            |(parent, type_, value)| CustomAttribute { parent, type_, value },
        )
    }

    /// Parse FieldMarshall row.
    ///
    /// ECMA-335 Section II.22.17.
    fn parse_field_marshal_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                // parent
                self.coded_index(&[Table::Field, Table::Param]),
                // native type (index into blob heap)
                self.blob_index(),
            ),
            |_| (),
        )
    }

    /// Parse DeclSecurity row.
    ///
    /// ECMA-335 Section II.22.11.
    fn parse_decl_security_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                // action
                le_u16,
                // parent
                self.coded_index(&[
                    Table::TypeDef,
                    Table::MethodDef,
                    Table::Assembly,
                ]),
                // permission set (index into blob heap)
                self.blob_index(),
            ),
            |_| (),
        )
    }

    /// Parse ClassLayout row.
    ///
    /// ECMA-335 Section II.22.8.
    fn parse_class_layout_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u16,                           // packing size
                le_u32,                           // class size
                self.table_index(Table::TypeDef), // parent (index into typedef table)
            ),
            |_| (),
        )
    }

    /// Parse FieldLayout row.
    ///
    /// ECMA-335 Section II.22.16.
    fn parse_field_layout_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u32,                         // offset
                self.table_index(Table::Field), // field (index into field table)
            ),
            |_| (),
        )
    }

    /// Parse EventMap row.
    ///
    /// ECMA-335 Section II.22.12.
    fn parse_event_map_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                self.table_index(Table::TypeDef), // parent
                self.table_index(Table::Event),   // event list
            ),
            |_| (),
        )
    }

    /// Parse Event row.
    ///
    /// ECMA-335 Section II.22.13.
    fn parse_event_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u16,
                self.string_index(),
                self.coded_index(Table::TYPE_DEF_OR_REF),
            ),
            |_| (),
        )
    }

    /// Parse PropertyMap row.
    ///
    /// ECMA-335 Section II.22.35.
    fn parse_property_map_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                self.table_index(Table::TypeDef),  // parent
                self.table_index(Table::Property), // event list
            ),
            |_| (),
        )
    }

    /// Parse Property row.
    ///
    /// ECMA-335 Section II.22.34.
    fn parse_property_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u16,              // flags
                self.string_index(), // name
                self.blob_index(),   // type
            ),
            |_| (),
        )
    }

    /// Parse MethodSemantics row.
    ///
    /// ECMA-335 Section II.22.28.
    fn parse_method_semantics_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u16, // semantics
                self.table_index(Table::MethodDef),
                self.coded_index(&[Table::Event, Table::Property]),
            ),
            |_| (),
        )
    }

    /// Parse MethodImpl row.
    ///
    /// ECMA-335 Section II.22.27.
    fn parse_method_impl_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                self.table_index(Table::TypeDef),
                self.coded_index(Table::METHOD_DEF_OR_REF),
                self.coded_index(Table::METHOD_DEF_OR_REF),
            ),
            |_| (),
        )
    }

    /// Parse ImplMap row.
    ///
    /// ECMA-335 Section II.22.22.
    fn parse_impl_map_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u16, // mapping flags
                self.coded_index(&[Table::Field, Table::MethodDef]),
                self.string_index(),
                self.table_index(Table::ModuleRef),
            ),
            |_| (),
        )
    }

    /// Parse FieldRVA row.
    ///
    /// ECMA-335 Section II.22.18.
    fn parse_field_rva_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = u32, Error = NomError<'a>> + '_ {
        map(
            (
                le_u32, // mapping flags
                self.table_index(Table::Field),
            ),
            |(rva, _)| rva,
        )
    }

    /// Parse Assembly row.
    ///
    /// ECMA-335 Section II.22.2.
    fn parse_assembly_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = Assembly<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                le_u32,                                                   // hash_alg
                le_u16,            // major_version
                le_u16,            // minor_version
                le_u16,            // build_number
                le_u16,            // revision
                le_u32,            // flags
                self.blob_index(), // public_key_or_token
                map(self.string_index(), |index| self.get_string(index)), // name
                map(self.string_index(), |index| self.get_string(index)), // culture
            ),
            |(
                _hash_alg,
                major_version,
                minor_version,
                build_number,
                revision,
                _flags,
                _public_key_or_token,
                name,
                culture,
            )| {
                Assembly {
                    name,
                    // Sometimes `culture` is an empty string (""), in such
                    // cases return `None` instead. Empty strings are against
                    // the specification, but it happens with files like:
                    // 756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59
                    culture: culture.filter(|&v| !v.is_empty()),
                    version: Version {
                        major_version,
                        minor_version,
                        build_number,
                        revision,
                    },
                }
            },
        )
    }

    /// Parse AssemblyRef row.
    ///
    /// ECMA-335 Section II.22.5.
    fn parse_assembly_ref_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = AssemblyRef<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                le_u16, // major_version
                le_u16, // minor_version
                le_u16, // build_number
                le_u16, // revision
                le_u32, // flags
                // public_key_or_token
                map(self.blob_index(), |index| self.get_blob(index)),
                // name
                map(self.string_index(), |index| self.get_string(index)),
                // culture
                map(self.string_index(), |index| self.get_string(index)),
                self.blob_index(), // hash_value
            ),
            |(
                major_version,
                minor_version,
                build_number,
                revision,
                _flags,
                public_key_or_token,
                name,
                _culture,
                _hash_value,
            )| AssemblyRef {
                // public_key_or_token sometimes have an empty string (""),
                // in such cases return `None` instead.
                public_key_or_token: public_key_or_token
                    .filter(|&v| !v.is_empty()),
                name,
                version: Version {
                    major_version,
                    minor_version,
                    build_number,
                    revision,
                },
            },
        )
    }

    /// Parse AssemblyRefProcessor row.
    ///
    /// ECMA-335 Section II.22.7.
    fn parse_assembly_ref_processor_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map((le_u32, self.table_index(Table::AssemblyRef)), |_| ())
    }

    /// Parse AssemblyRefOs row.
    ///
    /// ECMA-335 Section II.22.6.
    fn parse_assembly_ref_os_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u32, // os_platform_id
                le_u32, // os_major_version
                le_u32, // os_minor_version
                self.table_index(Table::AssemblyRef),
            ),
            |_| (),
        )
    }

    /// Parse File row.
    ///
    /// ECMA-335 Section II.22.19.
    fn parse_file_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u32,              // flags
                self.string_index(), // name
                self.blob_index(),   // hash_value
            ),
            |_| (),
        )
    }

    /// Parse ExportedType row.
    ///
    /// ECMA-335 Section II.22.14.
    fn parse_exported_type_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                le_u32,              // flags
                le_u32,              // type_def_if
                self.string_index(), // type_name
                self.string_index(), // type_namespace
                self.coded_index(&[
                    Table::File,
                    Table::AssemblyRef,
                    Table::ExportedType,
                ]),
            ),
            |_| (),
        )
    }

    /// Parse ManifestResource row.
    ///
    /// ECMA-335 Section II.22.24.
    fn parse_manifest_resource_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = Resource<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                le_u32,                                                   // offset
                le_u32, // flags
                map(self.string_index(), |index| self.get_string(index)), // name
                self.coded_index(&[
                    Table::File,
                    Table::AssemblyRef,
                    Table::Null,
                ]),
            ),
            |(offset, _, name, implementation)| {
                // data and offset is only set if the resources are located
                // in this file.
                if self.raw_resources.is_none()
                    || implementation.table != Table::File
                    || implementation.index != 0
                {
                    return Resource { name, data: None, offset: None };
                }

                // The length is encoded as a 32-bits integer at the start of
                // the resource data.
                let length = self
                    .raw_resources
                    .unwrap()
                    .get(offset as usize..)
                    .and_then(|data| {
                        le_u32::<&[u8], nom::error::Error<&'a [u8]>>(data).ok()
                    })
                    .map(|(_, length)| length as usize);

                if let Some(length) = length {
                    // Add 4 to skip the blob size.
                    let offset = offset.saturating_add(4);

                    let data = self.raw_resources.unwrap().get(
                        offset as usize
                            ..(offset as usize).saturating_add(length),
                    );

                    // The value in `offset` is relative to the start of
                    // `raw_resources`. But we want it relative to the start
                    // of the PE file, so we add `self.raw_resources_offset`.
                    let offset = self
                        .raw_resources_offset
                        .map(|base| base.saturating_add(offset));

                    Resource { name, data, offset }
                } else {
                    Resource { name, data: None, offset: None }
                }
            },
        )
    }

    /// Parse NestedClass row.
    ///
    /// ECMA-335 Section II.22.32.
    fn parse_nested_class_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = NestedClass, Error = NomError<'a>> + '_
    {
        map(
            (
                self.table_index(Table::TypeDef), // nested_class
                self.table_index(Table::TypeDef), // enclosing_class
            ),
            |(nested_class, enclosing_class)| NestedClass {
                nested_class,
                enclosing_class,
            },
        )
    }

    /// Parse GenericParam row.
    ///
    /// ECMA-335 Section II.22.20.
    fn parse_generic_param_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = GenericParam<'a>, Error = NomError<'a>> + '_
    {
        map(
            (
                le_u16, // number
                le_u16, // flags
                // owner
                self.coded_index(Table::TYPE_OR_METHOD_DEF),
                // name
                map(self.string_index(), |index| self.get_string(index)),
            ),
            |(_number, _flags, owner, name)| GenericParam { owner, name },
        )
    }

    /// Parse MethodSpec row.
    ///
    /// ECMA-335 Section II.22.29.
    fn parse_method_spec_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                self.coded_index(Table::METHOD_DEF_OR_REF), // method
                self.blob_index(),                          // instantiation
            ),
            |_| (),
        )
    }

    /// Parse GenericParamConstraint row.
    ///
    /// ECMA-335 Section II.22.21.
    fn parse_generic_param_constraint_row(
        &self,
    ) -> impl Parser<&'a [u8], Output = (), Error = NomError<'a>> + '_ {
        map(
            (
                self.table_index(Table::GenericParam),
                self.coded_index(Table::TYPE_DEF_OR_REF),
            ),
            |_| (),
        )
    }
}

/// CLIHeader
///
/// ECMA-335 Section II.25.3.3
struct CLIHeader {
    metadata: DirEntry,
    resources: DirEntry,
}

/// CLIMetadata
///
/// ECMA-335 Section II.24.2.1
struct CLIMetadata<'a> {
    stream_headers: Vec<StreamHeader<'a>>,
    version: &'a str,
}

/// StreamHeader
///
/// ECMA-335 Section II.24.2.2.
struct StreamHeader<'a> {
    offset: u32,    // stream offset, relative to metadata root
    size: u32,      // stream size
    name: &'a [u8], // stream name (examples: "#Strings", "#GUID", "#~")
}

/// An index into the `#Blob` stream.
#[derive(Clone, Copy)]
struct BlobIndex(u32);

/// An index into the `#GUID` stream.
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct GuidIndex(u32);

/// An index into the `#Strings` stream.
#[derive(Clone, Copy)]
struct StringIndex(u32);

/// Table numbers defined in the
#[derive(Clone, Copy, Debug, PartialEq)]
enum Table {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    FieldPtr = 0x03,
    Field = 0x04,
    MethodDefPtr = 0x05,
    MethodDef = 0x06,
    ParamPtr = 0x07,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0A,
    Constant = 0x0B,
    CustomAttribute = 0x0C,
    FieldMarshal = 0x0D,
    DeclSecurity = 0x0E,
    ClassLayout = 0x0F,
    FieldLayout = 0x10,
    StandaloneSig = 0x11,
    EventMap = 0x12,
    EventPtr = 0x13,
    Event = 0x14,
    PropertyMap = 0x15,
    PropertyPtr = 0x16,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1A,
    TypeSpec = 0x1B,
    ImplMap = 0x1C,
    FieldRva = 0x1D,
    EncLog = 0x1E,
    EncMap = 0x1F,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOs = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOs = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2A,
    MethodSpec = 0x2B,
    GenericParamConstraint = 0x2C,
    Null = 0xFF,
}

/// Table combinations used by coded indexes, as defined in
/// ECMA-335 Section II.24.2.6
impl Table {
    const TYPE_DEF_OR_REF: &'static [Table; 3] =
        &[Table::TypeDef, Table::TypeRef, Table::TypeSpec];

    const METHOD_DEF_OR_REF: &'static [Table; 2] =
        &[Table::MethodDef, Table::MemberRef];

    const TYPE_OR_METHOD_DEF: &'static [Table; 2] =
        &[Table::TypeDef, Table::MethodDef];

    const CUSTOM_ATTRIBUTE_TYPE: &'static [Table; 5] = &[
        Table::Null,
        Table::Null,
        Table::MethodDef,
        Table::MemberRef,
        Table::Null,
    ];

    const HAS_CUSTOM_ATTRIBUTE: &'static [Table; 22] = &[
        Table::MethodDef,
        Table::Field,
        Table::TypeRef,
        Table::TypeDef,
        Table::Param,
        Table::InterfaceImpl,
        Table::MemberRef,
        Table::Module,
        // The specification says that this should be the Permission table,
        // but we don't know what's the number for the permission table, it
        // seems to be an undocumented table, therefore we use Table::NULL.
        Table::Null,
        Table::Property,
        Table::Event,
        Table::StandaloneSig,
        Table::ModuleRef,
        Table::TypeSpec,
        Table::Assembly,
        Table::AssemblyRef,
        Table::File,
        Table::ExportedType,
        Table::ManifestResource,
        Table::GenericParam,
        Table::GenericParamConstraint,
        Table::MethodSpec,
    ];
}

/// Element types ECMA-335 Section II.23.1.16
#[derive(FromPrimitive, Debug, PartialEq)]
enum Type {
    End = 0x0,
    Void = 0x1,
    Bool = 0x2,
    Char = 0x3,
    I1 = 0x4,
    U1 = 0x5,
    I2 = 0x6,
    U2 = 0x7,
    I4 = 0x8,
    U4 = 0x9,
    I8 = 0xa,
    U8 = 0xb,
    R4 = 0xc,
    R8 = 0xd,
    String = 0xe,
    Ptr = 0xf,
    ByRef = 0x10,
    #[allow(clippy::enum_variant_names)]
    ValueType = 0x11,
    Class = 0x12,
    Var = 0x13,
    Array = 0x14,
    GenericInst = 0x15,
    TypedRef = 0x16,
    I = 0x18,
    U = 0x19,
    FnPtr = 0x1b,
    Object = 0x1c,
    SzArray = 0x1d,
    MVar = 0x1e,
    CModReqd = 0x1f,
    CModOpt = 0x20,
    Internal = 0x21,
    Modifier = 0x40,
    Sentinel = 0x41,
    Pinned = 0x45,
}

#[derive(Copy, Clone, Default)]
enum IndexSize {
    #[default]
    U16,
    U32,
}

#[derive(Debug)]
struct CodedIndex {
    table: Table,
    index: usize,
}

impl CodedIndex {
    /// Creates a [`CodedIndex`] from an `u32` value.
    ///
    /// The `tables` slice must contain the tables that the index can refer
    /// to. The lowest N bits in `u32` value are used for determining which
    /// of the tables the coded index is actually being referring to, while
    /// the upper 32-N bits are used for the index itself. The value of N
    /// depends on the number of tables.
    fn from_u32(tables: &[Table], u: u32) -> Result<Self, Error<'_>> {
        let tag_size = f64::log2(tables.len() as f64).ceil() as u32;
        let table_index = u & ((1 << tag_size) - 1);
        let table = tables
            .get(table_index as usize)
            .cloned()
            .ok_or(Error::InvalidCodedIndex)?;

        let index = u >> tag_size;

        // Indexes in are 1-based, but here we make them 0-based, so that
        // we can use them as Rust vector indexes.
        let index = index.saturating_sub(1) as usize;

        Ok(Self { table, index })
    }
}

#[derive(Debug)]
struct TypeRef<'a> {
    name: Option<&'a str>,
    namespace: Option<&'a str>,
}

impl<'a> TypeRef<'a> {
    /// Returns the name of the type.
    ///
    /// If the type is generic, the name will include a tick (`) followed with
    /// the number of generic arguments. This functions ignores the tick and
    /// everything that follows.
    pub fn plain_name(&self) -> Option<&'a str> {
        self.name
            .and_then(|name| name.rsplit_once('`'))
            .map(|(prefix, _)| prefix)
            .or(self.name)
    }
}

struct TypeDef<'a> {
    flags: u32,
    name: Option<&'a str>,
    namespace: Option<&'a str>,
    extends: CodedIndex,
    /// An index into the MethodDef table; it marks the first of a contiguous
    /// run of Methods owned by this Type. The run continues to the smaller of:
    ///  * the last row of the MethodDef table
    ///  * the next run of Methods, found by inspecting the method_list of the
    ///    types that comes after this one in the TypeDef table.
    method_list: usize,
}

impl<'a> TypeDef<'a> {
    /// Returns the name of the type.
    ///
    /// If the type is generic, the name will include a tick (`) followed with
    /// the number of generic arguments. This functions ignores the tick and
    /// everything that follows.
    pub fn plain_name(&self) -> Option<&'a str> {
        self.name
            .and_then(|name| name.rsplit_once('`'))
            .map(|(prefix, _)| prefix)
            .or(self.name)
    }
}

struct InterfaceImpl {
    class: usize, // offset into TypeDef
    interface: CodedIndex,
}

impl TypeDef<'_> {
    /// Returns true if this is a nested type.
    ///
    /// Whether a type is nested can be determined by the value of its
    /// Flags.Visibility sub-field, which should be one of the set
    ///
    /// {
    ///     NestedPublic,
    ///     NestedPrivate,
    ///     NestedFamily,
    ///     NestedAssembly,
    ///     NestedFamAndAssem,
    ///     NestedFamOrAssem
    /// }
    ///
    /// ECMA-335 II.22.37
    #[inline]
    fn is_nested(&self) -> bool {
        matches!(self.flags & 0x7, 2..=7)
    }

    #[inline]
    fn is_abstract(&self) -> bool {
        self.flags & 0x80 != 0
    }

    #[inline]
    fn is_sealed(&self) -> bool {
        self.flags & 0x100 != 0
    }

    #[inline]
    fn class_semantics(&self) -> ClassSemantics {
        if self.flags & 0x20 != 0 {
            ClassSemantics::Interface
        } else {
            ClassSemantics::Class
        }
    }

    fn visibility(&self) -> Visibility {
        match self.flags & 0x7 {
            0 => Visibility::Internal,
            1 => Visibility::Public,
            2 => Visibility::Public,
            3 => Visibility::Private,
            4 => Visibility::Protected,
            5 => Visibility::Internal,
            6 => Visibility::PrivateProtected,
            7 => Visibility::ProtectedInternal,
            _ => Visibility::Private,
        }
    }
}

#[derive(Debug)]
enum Visibility {
    Private,
    Public,
    Protected,
    Internal,
    PrivateProtected,
    ProtectedInternal,
}

impl Display for Visibility {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Private => write!(f, "private"),
            Visibility::Public => write!(f, "public"),
            Visibility::Protected => write!(f, "protected"),
            Visibility::Internal => write!(f, "internal"),
            Visibility::PrivateProtected => write!(f, "private protected"),
            Visibility::ProtectedInternal => write!(f, "protected internal"),
        }
    }
}

#[derive(Debug)]
enum ClassSemantics {
    Class,
    Interface,
}

impl Display for ClassSemantics {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassSemantics::Class => write!(f, "class"),
            ClassSemantics::Interface => write!(f, "interface"),
        }
    }
}

#[derive(Debug)]
pub struct MethodDef<'a> {
    flags: u16,
    name: Option<&'a str>,
    signature: Option<&'a [u8]>,
    param_list: usize,
}

impl MethodDef<'_> {
    #[inline]
    fn is_abstract(&self) -> bool {
        self.flags & 0x400 != 0
    }

    #[inline]
    fn is_final(&self) -> bool {
        self.flags & 0x20 != 0
    }

    #[inline]
    fn is_static(&self) -> bool {
        self.flags & 0x10 != 0
    }

    #[inline]
    fn is_virtual(&self) -> bool {
        self.flags & 0x40 != 0
    }

    fn visibility(&self) -> Visibility {
        match self.flags & 0x7 {
            1 => Visibility::Private,
            2 => Visibility::PrivateProtected,
            3 => Visibility::Internal,
            4 => Visibility::Protected,
            5 => Visibility::ProtectedInternal,
            6 => Visibility::Public,
            _ => Visibility::Private,
        }
    }
}

#[derive(Debug)]
pub struct MemberRef {
    class: CodedIndex,
}

#[derive(Debug)]
pub struct Assembly<'a> {
    version: Version,
    name: Option<&'a str>,
    culture: Option<&'a str>,
}

#[derive(Debug)]
pub struct AssemblyRef<'a> {
    version: Version,
    public_key_or_token: Option<&'a [u8]>,
    name: Option<&'a str>,
}

#[derive(Debug)]
pub struct Version {
    major_version: u16,
    minor_version: u16,
    build_number: u16,
    revision: u16,
}

#[derive(Debug)]
pub struct Constant<'a> {
    type_: Type,
    value: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct CustomAttribute<'a> {
    parent: CodedIndex,
    type_: CodedIndex,
    value: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct Resource<'a> {
    name: Option<&'a str>,
    offset: Option<u32>,
    data: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct Param<'a> {
    name: Option<&'a str>,
}

#[derive(Debug)]
pub struct GenericParam<'a> {
    owner: CodedIndex,
    name: Option<&'a str>,
}

#[derive(Debug)]
pub struct Class<'a> {
    full_name: Option<String>,
    base_types: Vec<String>,
    visibility: Visibility,
    semantics: ClassSemantics,
    is_abstract: bool,
    is_sealed: bool,
    generic_params: Vec<&'a str>,
    methods: Vec<Method<'a>>,
}

#[derive(Debug)]
pub struct Method<'a> {
    name: &'a str,
    generic_params: Vec<&'a str>,
    params: Vec<MethodParam<'a>>,
    return_type: Option<String>,
    visibility: Visibility,
    is_abstract: bool,
    is_static: bool,
    is_virtual: bool,
    is_final: bool,
}

#[derive(Debug)]
pub struct MethodParam<'a> {
    name: Cow<'a, str>,
    type_: Option<String>,
}

#[derive(Debug)]
struct NestedClass {
    nested_class: usize,    // index in the type_def table
    enclosing_class: usize, // index in the type_def table
}

impl From<Dotnet<'_>> for protos::dotnet::Dotnet {
    fn from(dotnet: Dotnet) -> Self {
        let mut result = protos::dotnet::Dotnet::new();

        result.set_is_dotnet(true);
        result.set_version(dotnet.version.to_string());
        if let Some(guids) = dotnet.parse_guids() {
            result.guids = Vec::with_capacity(guids.len());
            result
                .guids
                .extend(guids.into_iter().map(|guid| guid.to_string()));
        }
        result.typelib =
            dotnet.parse_typelib().map(|typelib| typelib.to_string());

        result.module_name = dotnet
            .modules
            .first()
            .and_then(|first| *first)
            .map(|first| first.to_string());

        result.assembly = dotnet
            .assemblies
            .first()
            .map(protos::dotnet::Assembly::from)
            .into();

        result.assembly_refs = Vec::with_capacity(dotnet.assembly_refs.len());
        result.assembly_refs.extend(
            dotnet.assembly_refs.iter().map(protos::dotnet::AssemblyRef::from),
        );

        result.modulerefs.extend(
            dotnet
                .module_refs
                .iter()
                .filter_map(|module_ref| module_ref.map(|s| s.to_string())),
        );

        result.streams = Vec::with_capacity(dotnet.stream_headers.len());
        result.streams.extend(
            dotnet.stream_headers.iter().map(protos::dotnet::Stream::from),
        );

        result.resources = Vec::with_capacity(dotnet.resources.len());
        result.resources.extend(
            dotnet.resources.iter().map(protos::dotnet::Resource::from),
        );

        result.classes = Vec::with_capacity(dotnet.type_defs.len());
        result
            .classes
            .extend(dotnet.iter_user_types().map(protos::dotnet::Class::from));

        result
            .constants
            .extend(dotnet.get_string_constants().map(|c| c.to_vec()));

        let user_strings = dotnet.parse_user_strings();
        result.user_strings = Vec::with_capacity(user_strings.len());
        result
            .user_strings
            .extend(user_strings.into_iter().map(|c| c.to_vec()));

        result.field_offsets = dotnet.field_offsets;

        result.set_number_of_streams(result.streams.len().try_into().unwrap());
        result.set_number_of_guids(result.guids.len().try_into().unwrap());
        result.set_number_of_classes(result.classes.len().try_into().unwrap());

        result.set_number_of_user_strings(
            result.user_strings.len().try_into().unwrap(),
        );

        result.set_number_of_assembly_refs(
            result.assembly_refs.len().try_into().unwrap(),
        );

        result.set_number_of_resources(
            result.resources.len().try_into().unwrap(),
        );

        result.set_number_of_constants(
            result.constants.len().try_into().unwrap(),
        );

        result.set_number_of_modulerefs(
            result.modulerefs.len().try_into().unwrap(),
        );

        result.set_number_of_field_offsets(
            result.field_offsets.len().try_into().unwrap(),
        );

        result
    }
}

impl From<&StreamHeader<'_>> for protos::dotnet::Stream {
    fn from(value: &StreamHeader) -> Self {
        let mut stream = protos::dotnet::Stream::new();
        stream.set_offset(value.offset);
        stream.set_size(value.size);
        stream.name =
            std::str::from_utf8(value.name).ok().map(|s| s.to_string());
        stream
    }
}

impl From<&Assembly<'_>> for protos::dotnet::Assembly {
    fn from(value: &Assembly<'_>) -> Self {
        let mut assembly = protos::dotnet::Assembly::new();
        assembly.name = value.name.map(|n| n.to_string());
        assembly.culture = value.culture.map(|c| c.to_string());
        assembly.version = MessageField::some((&value.version).into());
        assembly
    }
}

impl From<&AssemblyRef<'_>> for protos::dotnet::AssemblyRef {
    fn from(value: &AssemblyRef<'_>) -> Self {
        let mut assembly_ref = protos::dotnet::AssemblyRef::new();
        assembly_ref.name = value.name.map(|n| n.to_string());
        assembly_ref.public_key_or_token =
            value.public_key_or_token.map(|p| p.to_vec());
        assembly_ref.version = MessageField::some((&value.version).into());
        assembly_ref
    }
}

impl From<&Version> for protos::dotnet::Version {
    fn from(value: &Version) -> Self {
        protos::dotnet::Version {
            major: Some(value.major_version.into()),
            minor: Some(value.minor_version.into()),
            build_number: Some(value.build_number.into()),
            revision_number: Some(value.revision.into()),
            ..Default::default()
        }
    }
}

impl From<&Resource<'_>> for protos::dotnet::Resource {
    fn from(value: &Resource<'_>) -> Self {
        let mut resource = protos::dotnet::Resource::new();
        resource.name = value.name.map(|n| n.to_string());
        resource.offset = value.offset;
        resource.length = value.data.and_then(|d| d.len().try_into().ok());
        resource
    }
}

impl From<Class<'_>> for protos::dotnet::Class {
    fn from(value: Class<'_>) -> Self {
        let mut class = protos::dotnet::Class::new();
        if let Some(fullname) = &value.full_name {
            if let Some((namespace, name)) = fullname.rsplit_once('.') {
                class.set_namespace(namespace.to_string());
                class.set_name(name.to_string());
            } else {
                class.set_name(fullname.to_string());
            }
        }
        class.fullname = value.full_name;
        class.set_type(value.semantics.to_string());
        class.base_types = value.base_types;
        class.set_sealed(value.is_sealed);
        class.set_abstract(value.is_abstract);
        class.set_visibility(value.visibility.to_string());

        class.methods = Vec::with_capacity(value.methods.len());
        class.methods.extend(
            value.methods.into_iter().map(protos::dotnet::Method::from),
        );

        class.generic_parameters =
            Vec::with_capacity(value.generic_params.len());
        class
            .generic_parameters
            .extend(value.generic_params.into_iter().map(|s| s.to_string()));

        class.set_number_of_methods(class.methods.len().try_into().unwrap());

        class.set_number_of_base_types(
            class.base_types.len().try_into().unwrap(),
        );

        class.set_number_of_generic_parameters(
            class.generic_parameters.len().try_into().unwrap(),
        );

        class
    }
}

impl From<Method<'_>> for protos::dotnet::Method {
    fn from(value: Method<'_>) -> Self {
        let mut method = protos::dotnet::Method::new();
        method.set_name(value.name.to_string());
        method.set_visibility(value.visibility.to_string());
        method.set_abstract(value.is_abstract);
        method.set_virtual(value.is_virtual);
        method.set_final(value.is_final);
        method.set_static(value.is_static);
        method.parameters = Vec::with_capacity(value.params.len());
        method
            .parameters
            .extend(value.params.into_iter().map(protos::dotnet::Param::from));

        method.generic_parameters =
            Vec::with_capacity(value.generic_params.len());
        method
            .generic_parameters
            .extend(value.generic_params.into_iter().map(|s| s.to_string()));

        method.set_number_of_parameters(
            method.parameters.len().try_into().unwrap(),
        );

        method.set_number_of_generic_parameters(
            method.generic_parameters.len().try_into().unwrap(),
        );

        method.return_type = value.return_type;
        method
    }
}

impl From<MethodParam<'_>> for protos::dotnet::Param {
    fn from(value: MethodParam<'_>) -> Self {
        let mut param = protos::dotnet::Param::new();
        param.set_name(value.name.into_owned());
        param.type_ = value.type_;
        param
    }
}

/// Parses a variable-length unsigned integer.
///
/// Blob sizes and other integers in the ECMA-335 specification are encoded
/// as variable-length integers that can occupy 1, 2 or 4 bytes. The number
/// of bytes depends on the most significant bits of the first byte.
///
/// * If the most significant bit is 0, the integer is encoded as 1 byte,
///   and the value is stored in the remaining 7 bits.
///
/// * If the most significant bits are 10, the integer is encoded as 2 bytes,
///   and the value is stored in the remaining 14 bits.
///
/// * If the most significant bits are 110, the integer is encoded as 4 bytes,
///   and the value is stored the remaining 29 bits.
fn var_uint(input: &[u8]) -> IResult<&[u8], u32> {
    let (remainder, (_, value)) =
        bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(alt((
            bits_tag(0b0, 1u8).and(bits_take(7u8)),
            bits_tag(0b10, 2u8).and(bits_take(14u8)),
            bits_tag(0b110, 3u8).and(bits_take(29u8)),
        )))(input)?;

    Ok((remainder, value))
}

/// Parses a variable-length signed integer.
///
/// Similar to [`var_uint`] but for signed integers instead of unsigned.
/// The encoding mechanism is a bit more convoluted, and is described in
/// ECMA-325 II.23.2.
fn var_sint(input: &[u8]) -> IResult<&[u8], i32> {
    let (remainder, value) = bits::bits::<
        _,
        _,
        nom::error::Error<(&[u8], usize)>,
        _,
        _,
    >(alt((
        map(bits_tag(0b0, 1u8).and(bits_take(7u8)), |(_, x): (_, i32)| {
            if x & 0x01 != 0 { (x >> 1) - 0x40 } else { x >> 1 }
        }),
        map(bits_tag(0b10, 2u8).and(bits_take(14u8)), |(_, x): (_, i32)| {
            if x & 0x01 != 0 { (x >> 1) - 0x2000 } else { x >> 1 }
        }),
        map(bits_tag(0b110, 3u8).and(bits_take(29u8)), |(_, x): (_, i32)| {
            if x & 0x01 != 0 { (x >> 1) - 0x10000000 } else { x >> 1 }
        }),
    )))(input)?;

    Ok((remainder, value))
}

/// A string buffer that enforces a maximum byte length.
struct BoundedString {
    buf: String,
    max_len: usize,
}

impl BoundedString {
    #[inline]
    fn new(max_len: usize) -> Self {
        Self { buf: String::new(), max_len }
    }

    #[inline]
    fn into_inner(self) -> String {
        self.buf
    }

    #[inline]
    fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.buf.len() >= self.max_len
    }

    #[inline]
    fn reserve(&mut self, additional: usize) -> std::fmt::Result {
        if self.buf.len().saturating_add(additional) > self.max_len {
            return Err(std::fmt::Error);
        }
        self.buf.reserve(additional);
        Ok(())
    }

    #[inline]
    fn push_str(&mut self, s: &str) -> std::fmt::Result {
        if self.buf.len().saturating_add(s.len()) > self.max_len {
            return Err(std::fmt::Error);
        }
        self.buf.push_str(s);
        Ok(())
    }

    #[inline]
    fn push(&mut self, ch: char) -> std::fmt::Result {
        self.push_str(ch.encode_utf8(&mut [0; 4]))
    }
}

impl Write for BoundedString {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push_str(s)
    }

    #[inline]
    fn write_char(&mut self, c: char) -> std::fmt::Result {
        self.push(c)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn encode_var_uint(v: u32, out: &mut Vec<u8>) {
        if v <= 0x7F {
            out.push(v as u8);
        } else if v <= 0x3FFF {
            out.push(0x80 | ((v >> 8) as u8));
            out.push((v & 0xFF) as u8);
        } else {
            assert!(v <= 0x1FFF_FFFF);
            out.push(0xC0 | ((v >> 24) as u8));
            out.push(((v >> 16) & 0xFF) as u8);
            out.push(((v >> 8) & 0xFF) as u8);
            out.push((v & 0xFF) as u8);
        }
    }

    fn push_blob(stream: &mut Vec<u8>, payload: &[u8]) -> BlobIndex {
        let offset = stream.len() as u32;
        encode_var_uint(payload.len() as u32, stream);
        stream.extend_from_slice(payload);
        BlobIndex(offset)
    }

    fn typespec_coded_index_u32(idx: usize) -> u32 {
        (((idx as u32) + 1) << 2) | 2
    }

    #[test]
    fn var_uint() {
        assert_eq!(
            super::var_uint(&[0x00, 0x00]).unwrap(),
            ([0x00_u8].as_slice(), 0)
        );

        assert_eq!(
            super::var_uint(&[0x01, 0x00]).unwrap(),
            ([0x00_u8].as_slice(), 1)
        );

        assert_eq!(
            super::var_uint(&[0x7F, 0x00]).unwrap(),
            ([0x00_u8].as_slice(), 0x7F)
        );

        assert_eq!(
            super::var_uint(&[0x8A, 0x00]).unwrap(),
            ([].as_slice(), 0x0A00)
        );

        assert_eq!(
            super::var_uint(&[0xC1, 0x02, 0x03, 0x04]).unwrap(),
            ([].as_slice(), 0x01020304)
        );

        assert_eq!(
            super::var_uint(&[0xDF, 0xFF, 0xFF, 0xFF]).unwrap(),
            ([].as_slice(), 0x1FFFFFFF)
        );
    }

    #[test]
    fn var_sint() {
        assert_eq!(super::var_sint(&[0x6]).unwrap(), ([].as_slice(), 3));
        assert_eq!(super::var_sint(&[0x7B]).unwrap(), ([].as_slice(), -3));

        assert_eq!(
            super::var_sint(&[0x80, 0x80]).unwrap(),
            ([].as_slice(), 64)
        );

        assert_eq!(super::var_sint(&[0x01]).unwrap(), ([].as_slice(), -64));

        assert_eq!(
            super::var_sint(&[0xC0, 0x00, 0x40, 0x00]).unwrap(),
            ([].as_slice(), 8192)
        );

        assert_eq!(
            super::var_sint(&[0x80, 0x01]).unwrap(),
            ([].as_slice(), -8192)
        );

        assert_eq!(
            super::var_sint(&[0xDF, 0xFF, 0xFF, 0xFE]).unwrap(),
            ([].as_slice(), 268435455)
        );

        assert_eq!(
            super::var_sint(&[0xC0, 0x00, 0x00, 0x01]).unwrap(),
            ([].as_slice(), -268435456)
        );
    }

    #[test]
    fn typespec_dag_output_cap() {
        // Build a 6-layer GenericInst TypeSpec DAG with fan-out 32 per layer
        // (32^6 = 2^30 leaves if uncapped, well within MAX_RECURSION = 16).
        let mut blob_stream = vec![0u8];
        let mut type_specs = Vec::new();

        // Layer 0: GenericInst<int, int, ..., int> (32 args)
        let mut leaf = vec![Type::GenericInst as u8, Type::I4 as u8, 32];
        leaf.resize(leaf.len() + 32, Type::I4 as u8);
        type_specs.push(push_blob(&mut blob_stream, &leaf));

        // Layers 1..=5: each instantiates 32 copies of the previous TypeSpec.
        for prev in 0..5 {
            let mut node = vec![Type::GenericInst as u8, Type::I4 as u8, 32];
            for _ in 0..32 {
                node.push(Type::Class as u8);
                encode_var_uint(typespec_coded_index_u32(prev), &mut node);
            }
            type_specs.push(push_blob(&mut blob_stream, &node));
        }

        let root_blob = *type_specs.last().unwrap();
        let dotnet = Dotnet {
            data: &blob_stream,
            stream_headers: vec![StreamHeader {
                offset: 0,
                size: blob_stream.len() as u32,
                name: b"#Blob",
            }],
            blob_stream: Some(0),
            type_specs,
            ..Default::default()
        };

        let root_data = dotnet.get_blob(root_blob).unwrap();
        let mut output = BoundedString::new(Dotnet::MAX_TYPE_NAME_LEN);
        let mut depth = 0;

        let res = dotnet.parse_type_spec(
            root_data,
            &mut output,
            &mut depth,
            &[],
            &[],
        );

        assert!(matches!(res, Err(Error::OutputWrite(_))));
        assert!(output.len() <= Dotnet::MAX_TYPE_NAME_LEN);
    }

    #[test]
    fn oversized_strings_do_not_bypass_cap_or_deplete_budget() {
        let huge = "A".repeat(Dotnet::MAX_TYPE_NAME_LEN + 1);
        let dotnet = Dotnet {
            type_defs: vec![
                TypeDef {
                    flags: 0x1, // Public, non-nested
                    name: Some(&huge),
                    namespace: Some("Ns"),
                    extends: CodedIndex { table: Table::TypeDef, index: 0 },
                    method_list: 0,
                },
                TypeDef {
                    flags: 0x1,
                    name: Some("ValidClass"),
                    namespace: Some("Ns"),
                    extends: CodedIndex { table: Table::TypeRef, index: 0 },
                    method_list: 0,
                },
            ],
            type_refs: vec![TypeRef {
                name: Some(&huge),
                namespace: Some("Ns"),
            }],
            ..Default::default()
        };

        let classes: Vec<_> = dotnet.iter_user_types().collect();
        assert_eq!(classes.len(), 2);
        // Oversized TypeDef full_name is rejected cleanly without exhausting
        // the budget for subsequent valid classes.
        assert_eq!(classes[0].full_name, None);
        assert_eq!(classes[1].full_name.as_deref(), Some("Ns.ValidClass"));
        // Oversized TypeRef base type is also rejected cleanly.
        assert!(classes[1].base_types.is_empty());
    }

    #[test]
    fn method_param_count_cap() {
        // Signature with MAX_PARAMS (1000) regular params must be rejected.
        let mut bad_sig = vec![0x00]; // flags
        encode_var_uint(Dotnet::MAX_PARAMS, &mut bad_sig);
        bad_sig.push(Type::Void as u8);
        bad_sig.resize(
            bad_sig.len() + Dotnet::MAX_PARAMS as usize,
            Type::I4 as u8,
        );

        // Signature with 2 regular params must succeed.
        let good_sig =
            [0x00, 0x02, Type::Void as u8, Type::I4 as u8, Type::U4 as u8];

        let dotnet = Dotnet {
            type_defs: vec![TypeDef {
                flags: 0x1,
                name: Some("C"),
                namespace: None,
                extends: CodedIndex { table: Table::TypeDef, index: 1 },
                method_list: 0,
            }],
            method_defs: vec![
                MethodDef {
                    flags: 0x6,
                    name: Some("TooManyParams"),
                    signature: Some(&bad_sig),
                    param_list: 0,
                },
                MethodDef {
                    flags: 0x6,
                    name: Some("OkParams"),
                    signature: Some(&good_sig),
                    param_list: 0,
                },
            ],
            ..Default::default()
        };

        let classes: Vec<_> = dotnet.iter_user_types().collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].methods.len(), 1);
        assert_eq!(classes[0].methods[0].name, "OkParams");
        assert_eq!(classes[0].methods[0].params.len(), 2);
    }

    #[test]
    fn cumulative_type_name_budget_caps_shared_blob_amplification() {
        // Create a TypeSpec that formats to ~8 KiB (< MAX_TYPE_NAME_LEN = 16 KiB).
        let mut blob_stream = vec![0u8];
        let mut ts0 = vec![Type::GenericInst as u8, Type::I4 as u8, 64];
        ts0.resize(ts0.len() + 64, Type::I4 as u8); // ~260 bytes formatted

        let mut ts1 = vec![Type::GenericInst as u8, Type::I4 as u8, 30];
        for _ in 0..30 {
            ts1.push(Type::Class as u8);
            encode_var_uint(typespec_coded_index_u32(0), &mut ts1);
        } // ~7,800 bytes formatted (< 16 KiB)

        let b0 = push_blob(&mut blob_stream, &ts0);
        let b1 = push_blob(&mut blob_stream, &ts1);

        // One shared method signature with 100 params of TypeSpec[1] (~780 KiB
        // per method). Across 100 methods that would be ~78 MiB without the
        // 32 MiB cumulative budget.
        let mut sig = vec![0x00, 100, Type::Void as u8];
        for _ in 0..100 {
            sig.push(Type::Class as u8);
            encode_var_uint(typespec_coded_index_u32(1), &mut sig);
        }

        let method_defs = (0..100)
            .map(|_| MethodDef {
                flags: 0x6,
                name: Some("M"),
                signature: Some(&sig),
                param_list: 0,
            })
            .collect();

        let dotnet = Dotnet {
            data: &blob_stream,
            stream_headers: vec![StreamHeader {
                offset: 0,
                size: blob_stream.len() as u32,
                name: b"#Blob",
            }],
            blob_stream: Some(0),
            type_specs: vec![b0, b1],
            type_defs: vec![TypeDef {
                flags: 0x1,
                name: Some("Amplifier"),
                namespace: None,
                extends: CodedIndex { table: Table::TypeDef, index: 1 },
                method_list: 0,
            }],
            method_defs,
            ..Default::default()
        };

        let classes: Vec<_> = dotnet.iter_user_types().collect();
        assert_eq!(classes.len(), 1);
        // Some methods succeed before the budget runs out, but not all 100.
        assert!(!classes[0].methods.is_empty());
        assert!(classes[0].methods.len() < 100);

        let total_retained_bytes: usize = classes[0]
            .methods
            .iter()
            .flat_map(|m| m.params.iter())
            .filter_map(|p| p.type_.as_ref())
            .map(|s| s.len())
            .sum();
        assert!(total_retained_bytes <= Dotnet::MAX_METHOD_SIG_BYTES);
    }
}
