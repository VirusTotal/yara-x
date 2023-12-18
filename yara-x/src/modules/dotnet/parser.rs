use std::cell::OnceCell;
use std::ffi::CStr;
use std::fmt::{Display, Formatter, Write};

use bits::complete::tag as bits_tag;
use bits::complete::take as bits_take;
use itertools::Itertools;
use nom::branch::alt;
use nom::bytes::complete::{take, take_till};
use nom::combinator::{cond, map, map_opt, map_parser, map_res};
use nom::multi::{count, length_count, length_data, many_m_n};
use nom::number::complete::{le_u16, le_u32, le_u64, u8};
use nom::sequence::tuple;
use nom::{bits, AsChar, IResult, Parser};
use num_derive::FromPrimitive;
use protobuf::MessageField;
use uuid::Uuid;

use crate::modules::pe::parser::{DirEntry, PE};
use crate::modules::protos;

type NomError<'a> = nom::Err<nom::error::Error<&'a [u8]>>;

pub enum Error<'a> {
    InvalidDotNet,
    ParseError(NomError<'a>),
}

/// An .NET file parser.
#[derive(Default)]
pub struct Dotnet<'a> {
    /// Slice that contains the whole .NET file.
    data: &'a [u8],
    /// Version string.
    version: &'a [u8],
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
    /// Index within `stream_headers` for the `#~` stream.
    tilde_stream: Option<usize>,
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
    /// Modules table.
    modules: Vec<&'a str>,
    /// TypeRef table.
    type_refs: Vec<TypeRef<'a>>,
    /// TypeDef table.
    type_defs: Vec<TypeDef<'a>>,
    /// TypeSpec table.
    type_specs: Vec<BlobIndex>,
    /// MemberRef table.
    member_refs: Vec<MemberRef<'a>>,
    /// InterfaceImpl table.
    interface_impls: Vec<InterfaceImpl>,
    /// FieldRVA table.
    field_rvas: Vec<u32>,
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
        let pe = PE::parse(data).map_err(Error::ParseError)?;

        let (_, _, cli_header) = pe
            .get_dir_entry_data(PE::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            .ok_or(Error::InvalidDotNet)?;

        let (_, cli_header) =
            Self::parse_cli_header(cli_header).map_err(Error::ParseError)?;

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

        let (_, mut metadata) = Self::parse_metadata_root(raw_metadata)
            .map_err(Error::ParseError)?;

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
            tilde_stream,
            strings_stream,
            us_stream,
            blob_stream,
            guid_stream,
            ..Default::default()
        };

        dotnet
            .parse_tilde_stream(
                dotnet.get_stream(dotnet.tilde_stream.unwrap()).unwrap(),
            )
            .map_err(Error::ParseError)?;

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

    pub fn get_string_constants(&self) -> impl Iterator<Item = &[u8]> {
        self.constants.iter().filter_map(|c| {
            if c.type_ == Type::String {
                c.value
            } else {
                None
            }
        })
    }
}

impl<'a> Dotnet<'a> {
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
        let (data, length) = varint(data).ok()?;
        data.get(0..length)
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

    fn get_constant(&self, index: &CodedIndex) -> Option<&Constant> {
        if index.table != Table::Constant {
            return None;
        }
        self.constants.get(index.index)
    }

    fn get_member_ref(&self, index: &CodedIndex) -> Option<&MemberRef> {
        if index.table != Table::MemberRef {
            return None;
        }
        self.member_refs.get(index.index)
    }

    fn get_type_ref(&self, index: &CodedIndex) -> Option<&TypeRef> {
        if index.table != Table::TypeRef {
            return None;
        }
        self.type_refs.get(index.index)
    }

    fn get_type_spec(&self, index: &CodedIndex) -> Option<BlobIndex> {
        if index.table != Table::TypeSpec {
            return None;
        }
        self.type_specs.get(index.index).cloned()
    }

    fn get_assembly_ref(&self, index: &CodedIndex) -> Option<&Assembly> {
        if index.table != Table::AssemblyRef {
            return None;
        }
        self.assemblies.get(index.index)
    }
}

impl<'a> Dotnet<'a> {
    fn parse_cli_header(input: &[u8]) -> IResult<&[u8], CLIHeader> {
        map(
            tuple((
                le_u32,              // size
                le_u16,              // major_runtime_version
                le_u16,              // minor_runtime_version
                PE::parse_dir_entry, // metadata
                le_u32,              // flags
                le_u32,              // entry_point_token
                PE::parse_dir_entry, // resources,
                PE::parse_dir_entry, // strong_name_signature
            )),
            |(
                _,
                major_runtime_version,
                minor_runtime_version,
                metadata,
                flags,
                entry_point_token,
                resources,
                strong_name_signature,
            )| {
                CLIHeader {
                    major_runtime_version,
                    minor_runtime_version,
                    metadata,
                    flags,
                    entry_point_token,
                    resources,
                    strong_name_signature,
                }
            },
        )(input)
    }

    /// Parses metadata root.
    ///
    /// ECMA-335 Section II.24.2.1.
    fn parse_metadata_root(input: &[u8]) -> IResult<&[u8], CLIMetadata> {
        map(
            tuple((
                le_u32, // magic == 0x424A5342
                le_u16, // major_version
                le_u16, // minor_version
                le_u32, // reserved
                // length + version string. The length is <= 255 according to
                // the specification, but we don't enforce it. The length
                // includes any padding added to align the next field to a
                // 4 byte boundary. The string is null-terminated.
                map_parser(length_data(le_u32), take_till(|c| c == 0)),
                le_u16, // flags (reserved)
                // number of streams, say N, followed by array of N stream
                // headers
                length_count(le_u16, Self::parse_stream_header),
            )),
            |(
                _magic,
                major_version,
                minor_version,
                _reserved,
                version,
                _flags,
                stream_headers,
            )| {
                CLIMetadata {
                    major_version,
                    minor_version,
                    stream_headers,
                    version,
                }
            },
        )(input)
    }

    /// Parses a stream header.
    fn parse_stream_header(input: &[u8]) -> IResult<&[u8], StreamHeader> {
        let (remaining, (offset, size, name)) = tuple((
            le_u32,                // offset
            le_u32,                // size
            take_till(|c| c == 0), // name, null-terminated ASCII string
        ))(input)?;

        // The name is padded with zeroes up to the next 4 bytes boundary,
        // lets consume the padding, which includes the null-terminator.
        // TODO: `usize::next_multiple_of` was stabilized in Rust 1.73.
        // Once we bump the MSRV to 1.73 we can stop using `num`.
        // https://doc.rust-lang.org/std/primitive.u32.html#method.div_ceil
        let padding =
            num::Integer::next_multiple_of(&(name.len() + 1), &4) - name.len();

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
        // The `#~` starts with a header that is followed the tables.
        let (remainder, (_, _, _, heap_sizes, _, valid, _sorted)) =
            tuple((
                le_u32, // reserved, always 0
                u8,     // major_version, shall be 2
                u8,     // minor_version; shall be 0
                u8,     // heap_sizes
                u8,     // reserved, always 1
                le_u64, // valid
                le_u64, // sorted
            ))(input)?;

        // The number of tables is the number of bits set to 1 in the `valid`
        // field.
        let num_tables = u64::count_ones(valid);

        // Then follows an array of `num_tables` items with the number of rows
        // per each table that is present.
        let (mut remainder, num_rows_per_present_table) = count(
            map(le_u32, |v| v as usize),
            num_tables as usize,
        )(remainder)?;

        let mut num_rows_per_present_table =
            num_rows_per_present_table.into_iter();

        // `num_rows_per_present_table` contains an entry per each table
        // that is present. But we need an array with an entry per table,
        // no matter if its present or not. Of course, tables that are not
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

        (remainder, self.modules) = count(
            self.parse_module_row(),
            self.num_rows(Table::Module),
        )(remainder)?;

        (remainder, self.type_refs) = count(
            self.parse_type_ref_row(),
            self.num_rows(Table::TypeRef),
        )(remainder)?;

        (remainder, self.type_defs) = count(
            self.parse_type_def_row(),
            self.num_rows(Table::TypeDef),
        )(remainder)?;

        (remainder, _) = count(
            self.table_index(Table::Field),
            self.num_rows(Table::FieldPtr),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_field_row(),
            self.num_rows(Table::Field),
        )(remainder)?;

        (remainder, _) = count(
            self.table_index(Table::MethodDef),
            self.num_rows(Table::MethodDefPtr),
        )(remainder)?;

        (remainder, self.method_defs) = count(
            self.parse_method_def_row(),
            self.num_rows(Table::MethodDef),
        )(remainder)?;

        (remainder, _) = count(
            self.table_index(Table::Param),
            self.num_rows(Table::ParamPtr),
        )(remainder)?;

        (remainder, self.params) = count(
            self.parse_param_row(),
            self.num_rows(Table::Param),
        )(remainder)?;

        (remainder, self.interface_impls) = count(
            self.parse_interface_impl_row(),
            self.num_rows(Table::InterfaceImpl),
        )(remainder)?;

        (remainder, self.member_refs) = count(
            self.parse_member_ref_row(),
            self.num_rows(Table::MemberRef),
        )(remainder)?;

        (remainder, self.constants) = count(
            self.parse_constant_row(),
            self.num_rows(Table::Constant),
        )(remainder)?;

        (remainder, self.custom_attributes) = count(
            self.parse_custom_attribute_row(),
            self.num_rows(Table::CustomAttribute),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_field_marshal_row(),
            self.num_rows(Table::FieldMarshal),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_decl_security_row(),
            self.num_rows(Table::DeclSecurity),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_class_layout_row(),
            self.num_rows(Table::ClassLayout),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_field_layout_row(),
            self.num_rows(Table::FieldLayout),
        )(remainder)?;

        (remainder, _) = count(
            self.blob_index(),
            self.num_rows(Table::StandaloneSig),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_event_map_row(),
            self.num_rows(Table::EventMap),
        )(remainder)?;

        (remainder, _) = count(
            self.table_index(Table::Event),
            self.num_rows(Table::EventPtr),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_event_row(),
            self.num_rows(Table::Event),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_property_map_row(),
            self.num_rows(Table::PropertyMap),
        )(remainder)?;

        (remainder, _) = count(
            self.table_index(Table::Property),
            self.num_rows(Table::PropertyPtr),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_property_row(),
            self.num_rows(Table::Property),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_method_semantics_row(),
            self.num_rows(Table::MethodSemantics),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_method_impl_row(),
            self.num_rows(Table::MethodImpl),
        )(remainder)?;

        (remainder, self.module_refs) = count(
            map(self.string_index(), |index| self.get_string(index)),
            self.num_rows(Table::ModuleRef),
        )(remainder)?;

        (remainder, self.type_specs) = count(
            self.blob_index(),
            self.num_rows(Table::TypeSpec),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_impl_map_row(),
            self.num_rows(Table::ImplMap),
        )(remainder)?;

        (remainder, self.field_rvas) = count(
            self.parse_field_rva_row(),
            self.num_rows(Table::FieldRva),
        )(remainder)?;

        (remainder, _) =
            count(take(8_usize), self.num_rows(Table::EncLog))(remainder)?;

        (remainder, _) =
            count(take(4_usize), self.num_rows(Table::EncMap))(remainder)?;

        (remainder, self.assemblies) = count(
            self.parse_assembly_row(),
            self.num_rows(Table::Assembly),
        )(remainder)?;

        (remainder, _) = count(
            take(4_usize),
            self.num_rows(Table::AssemblyProcessor),
        )(remainder)?;

        (remainder, _) = count(
            take(12_usize),
            self.num_rows(Table::AssemblyOs),
        )(remainder)?;

        (remainder, self.assembly_refs) = count(
            self.parse_assembly_ref_row(),
            self.num_rows(Table::AssemblyRef),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_assembly_ref_processor_row(),
            self.num_rows(Table::AssemblyRefProcessor),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_assembly_ref_os_row(),
            self.num_rows(Table::AssemblyRefOs),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_file_row(),
            self.num_rows(Table::File),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_exported_type_row(),
            self.num_rows(Table::ExportedType),
        )(remainder)?;

        (remainder, self.resources) = count(
            self.parse_manifest_resource_row(),
            self.num_rows(Table::ManifestResource),
        )(remainder)?;

        (remainder, self.nested_classes) = count(
            self.parse_nested_class_row(),
            self.num_rows(Table::NestedClass),
        )(remainder)?;

        (remainder, self.generic_params) = count(
            self.parse_generic_param_row(),
            self.num_rows(Table::GenericParam),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_method_spec_row(),
            self.num_rows(Table::MethodSpec),
        )(remainder)?;

        (remainder, _) = count(
            self.parse_generic_param_constraint_row(),
            self.num_rows(Table::GenericParamConstraint),
        )(remainder)?;

        Ok((remainder, ()))
    }

    fn parse_user_types(&self) -> Vec<Class<'a>> {
        let mut classes = Vec::new();
        for (idx, type_def) in self.type_defs.iter().enumerate() {
            // Skip type definitions with invalid (empty) names, and the
            // "<Module>" pseudo-class.
            if !type_def.name.is_some_and(|name| name != "<Module>") {
                continue;
            }

            let generic_param_names: Vec<_> = self
                .generic_params
                .iter()
                .filter_map(|param| {
                    if param.owner.index == idx {
                        Some(param.name)
                    } else {
                        None
                    }
                })
                .collect();

            // The methods belonging to this type in in the MethodDef table
            // go from the index specified by `method_list` to the index specified
            // by the next type's `method_list`. If this is the last type, then
            // it goes to the end of the MethodDef table.
            let method_defs =
                if let Some(next_type_def) = self.type_defs.get(idx + 1) {
                    self.method_defs
                        .get(type_def.method_list..next_type_def.method_list)
                } else {
                    self.method_defs.get(type_def.method_list..)
                };

            let methods = if let Some(method_defs) = method_defs {
                method_defs
                    .iter()
                    .filter_map(|method_def| {
                        self.convert_method_def(method_def)
                    })
                    .collect()
            } else {
                vec![]
            };

            // `base_types` will contain the names of the classes the current
            // class inherits from.
            let mut base_types = Vec::new();

            // If the current class extends some other class, add the full name
            // of this other class to `base_types`.
            if let Some(name) =
                self.type_def_or_ref_fullname(&type_def.extends)
            {
                base_types.push(name)
            }

            // For every interface implemented by the current class, add its
            // full name to `base_types`.
            base_types.extend(self.interface_impls.iter().filter_map(
                |interface_impl| {
                    if interface_impl.class == idx {
                        self.type_def_or_ref_fullname(
                            &interface_impl.interface,
                        )
                    } else {
                        None
                    }
                },
            ));

            classes.push(Class {
                name: type_def.plain_name().unwrap(),
                full_name: self.type_full_name(idx),
                base_types,
                visibility: type_def.visibility(),
                semantics: type_def.class_semantics(),
                is_abstract: type_def.is_abstract(),
                is_sealed: type_def.is_sealed(),
                methods,
            });
        }
        classes
    }

    fn convert_method_def(
        &self,
        method_def: &MethodDef<'a>,
    ) -> Option<Method<'a>> {
        let (remainder, flags) =
            u8::<&[u8], nom::error::Error<&'a [u8]>>(method_def.signature?)
                .ok()?;

        let (remainder, (_generic_param_count, param_count)) =
            tuple((
                // Generic param count, present only if
                // SIG_FLAG_GENERIC flag is set.
                cond(flags & 0x10 != 0, varint),
                // Regular param count.
                varint,
            ))(remainder)
            .ok()?;

        let mut return_type = String::new();
        let mut remainder =
            self.parse_type_spec(remainder, &mut return_type).ok()?;

        let parameters = self
            .params
            .get(method_def.param_list..method_def.param_list + param_count);

        let mut method_params = Vec::new();

        if let Some(parameters) = parameters {
            for param in parameters {
                let mut param_type = String::new();
                remainder =
                    self.parse_type_spec(remainder, &mut param_type).ok()?;
                method_params.push(MethodParam {
                    name: param.name,
                    type_: Some(param_type),
                })
            }
        }

        // Return type for constructors is always set to None, which is YARA sees
        // as undefined, for FileInfo compatibility.
        let return_type =
            if matches!(method_def.name, Some(".ctor") | Some(".cctor")) {
                None
            } else {
                Some(return_type)
            };

        Some(Method {
            name: method_def.name?,
            parameters: method_params,
            return_type,
            visibility: method_def.visibility(),
            is_final: method_def.is_final(),
            is_abstract: method_def.is_abstract(),
            is_virtual: method_def.is_virtual(),
            is_static: method_def.is_static(),
        })
    }

    /// Given an index into the `type_defs` table, returns its full name.
    ///
    /// When the type is not nested the full name is simply `namespace.name`,
    /// when the type is a nested one, the full name includes the name of
    /// its parent type as well.
    fn type_full_name(&self, type_def_idx: usize) -> Option<String> {
        let mut next_idx = Some(type_def_idx);
        let mut result = Vec::new();

        while let Some(idx) = next_idx.take() {
            let type_def = self.type_defs.get(idx)?;

            result.push(type_def.plain_name()?);

            if let Some(namespace) = type_def.namespace {
                result.push(namespace)
            }

            // If the type is a nested one, an entry in `nested_classes` must
            // exist where `nested_class` is the index of the current type
            // and `enclosing_class` is the index of the parent type. Both
            // are indexes into the `type_defs` table. `next_idx` will
            // contain the index of the parent type.
            if type_def.is_nested() {
                next_idx = self
                    .nested_classes
                    .iter()
                    .find(|c| c.nested_class == idx)
                    .map(|c| c.enclosing_class);
            }
        }

        // The innermost type is pushed first into the list, but it should be
        // the last one in the resulting name. So the list must be iterated
        // backwards.
        Some(result.iter().rev().join("."))
    }

    fn type_def_or_ref_fullname(&self, index: &CodedIndex) -> Option<String> {
        match index.table {
            Table::TypeDef => self.type_full_name(index.index),
            Table::TypeRef => self.get_type_ref(index).and_then(|t| {
                match (t.namespace, t.plain_name()) {
                    (Some(namespace), Some(name)) => {
                        Some(format!("{}.{}", namespace, name))
                    }
                    (_, name) => name.map(|n| n.to_string()),
                }
            }),
            Table::TypeSpec => {
                let mut name = String::new();
                self.get_type_spec(index)
                    .and_then(|blob_index| self.get_blob(blob_index))
                    .map(|data| self.parse_type_spec(data, &mut name));
                Some(name)
            }
            _ => unreachable!(),
        }
    }

    /// Parses a type spec blob.
    ///
    /// ECMA-335 Section II.23.2.12
    fn parse_type_spec(
        &self,
        input: &'a [u8],
        output: &mut dyn Write,
    ) -> Result<&'a [u8], std::fmt::Error> {
        let (mut remainder, type_) =
            map_opt(u8, num::FromPrimitive::from_u8)(input)
                .map_err(|_: NomError| std::fmt::Error)?;

        match type_ {
            Type::Void => write!(output, "void")?,
            Type::Bool => write!(output, "bool")?,
            Type::Char => write!(output, "char")?,
            Type::I1 => write!(output, "sbyte")?,
            Type::U1 => write!(output, "byte")?,
            Type::I2 => write!(output, "short")?,
            Type::U2 => write!(output, "ushort")?,
            Type::I4 => write!(output, "int")?,
            Type::U4 => write!(output, "uint")?,
            Type::I8 => write!(output, "long")?,
            Type::U8 => write!(output, "ulong")?,
            Type::R4 => write!(output, "float")?,
            Type::R8 => write!(output, "double")?,
            Type::Object => write!(output, "object")?,
            Type::String => write!(output, "string")?,
            Type::TypedRef => write!(output, "TypedReference")?,
            Type::I => write!(output, "IntPtr")?,
            Type::U => write!(output, "UintPtr")?,
            Type::Ptr => {
                write!(output, "Ptr<")?;
                remainder = self.parse_type_spec(remainder, output)?;
                write!(output, ">")?;
            }
            Type::ByRef => {
                write!(output, "ref ")?;
                remainder = self.parse_type_spec(remainder, output)?;
            }
            Type::ValueType | Type::Class => {
                let index;

                (remainder, index) = varint(remainder)
                    .map_err(|_: NomError| std::fmt::Error)?;

                write!(
                    output,
                    "{}",
                    self.type_def_or_ref_fullname(&CodedIndex::new(
                        Table::TYPE_DEF_OR_REF,
                        index
                    ))
                    .ok_or(std::fmt::Error)?
                )?;
            }
            Type::Var | Type::MVar => {
                let index;

                (remainder, index) = varint(remainder)
                    .map_err(|_: NomError| std::fmt::Error)?;

                let name = self
                    .generic_params
                    .get(index)
                    .and_then(|p| p.name)
                    .ok_or(std::fmt::Error)?;

                write!(output, "{}", name)?;
            }
            Type::Array => {
                let dimensions;
                let sizes;
                let lower_bounds;

                remainder = self.parse_type_spec(remainder, output)?;

                (remainder, (dimensions, sizes, lower_bounds)) =
                    tuple((
                        // dimensions
                        varint,
                        // number of sizes and the sizes themselves.
                        length_count(varint, varint),
                        // number of lower bounds and the lower bounds themselves.
                        length_count(varint, varint),
                    ))(remainder)
                    .map_err(|_: NomError| std::fmt::Error)?;

                write!(output, "[")?;
                for i in 0..dimensions {
                    let size = sizes.get(i).cloned().unwrap_or(0);
                    if size > 0 {
                        let l = lower_bounds.get(i).cloned().unwrap_or(0);
                        let h = l + size - 1;
                        write!(output, "{}...{}", l, h)?;
                    }
                    // If not the last item, prepend a comma.
                    if i + 1 != dimensions {
                        write!(output, ",")?;
                    }
                }
                write!(output, "]")?;
            }
            Type::SzArray => {
                remainder = self.parse_type_spec(remainder, output)?;
                write!(output, "[]")?;
            }
            Type::GenericInst => {
                let gen_count;

                remainder = self.parse_type_spec(remainder, output)?;

                (remainder, gen_count) = varint(remainder)
                    .map_err(|_: NomError| std::fmt::Error)?;

                // TODO: gen_count > MAX_GEN_COUNT

                write!(output, "<")?;
                for i in 1..=gen_count {
                    remainder = self.parse_type_spec(remainder, output)?;
                    if i < gen_count {
                        write!(output, ",")?;
                    }
                }
                write!(output, ">")?;
            }
            Type::FnPtr => {
                let param_count;

                // Skip flags and read param count.
                (remainder, (_, param_count)) = tuple((u8, varint))(remainder)
                    .map_err(|_: NomError| std::fmt::Error)?;

                // TODO: check param_count <= MAX_PARAM_COUNT

                write!(output, "FnPtr<")?;
                remainder = self.parse_type_spec(remainder, output)?;
                write!(output, "(")?;
                for i in 1..=param_count {
                    remainder = self.parse_type_spec(remainder, output)?;
                    if i < param_count {
                        write!(output, ", ")?;
                    }
                }
                write!(output, ")>")?;
            }
            Type::CModReqd | Type::CModOpt => {
                (remainder, _) = varint(remainder)
                    .map_err(|_: NomError| std::fmt::Error)?;
                remainder = self.parse_type_spec(remainder, output)?;
            }
            _ => {}
        };

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

    /// Returns a parser of an index in the `#Strings` stream.
    #[inline]
    fn string_index(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], StringIndex> {
        map(self.index(self.string_index_size), StringIndex)
    }

    /// Returns a parser for an index in the `#GUID` stream.
    #[inline]
    fn guid_index(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], GuidIndex> {
        map(self.index(self.guid_index_size), GuidIndex)
    }

    /// Returns a parser for an index in the `#Blob` stream.
    #[inline]
    fn blob_index(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], BlobIndex> {
        map(self.index(self.blob_index_size), BlobIndex)
    }

    /// Returns a parser for an index in the given table.
    #[inline]
    fn table_index(
        &self,
        table: Table,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], usize> + '_ {
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
    /// can fit in a 16 bits coded index is `2^(16 - tag_size)` (remember, some
    /// bits are used for encoding the table), so if the largest table has less
    /// than `2^(16 - tag_size)` elements, the coded index is 16 bits. Otherwise
    /// it will be 32 bits long.
    fn coded_index<'s>(
        &'s self,
        tables: &'s [Table],
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], CodedIndex> + 's {
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
            let (remainder, index) = self.index(index_size)(input)?;

            Ok((remainder, CodedIndex::new(tables, index as usize)))
        }
    }

    /// Parse Module row.
    ///
    /// ECMA-335 Section II.22.30
    fn parse_module_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], &'a str> + '_ {
        map(
            tuple((
                // generation (reserved, shall be zero).
                le_u16,
                // name (index into the `#String` heap)
                map_opt(self.string_index(), |index| self.get_string(index)),
                // mvid (index into the `#GUID` heap)
                self.guid_index(),
                // enc_id (index into the `#GUID` heap)
                self.guid_index(),
                // enc_base_id (index into the `#GUID` heap)
                self.guid_index(),
            )),
            |(_, name, _, _, _)| name,
        )
    }

    /// Parse TypeRef row.
    ///
    /// ECMA-335 Section II.22.38
    fn parse_type_ref_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], TypeRef> + '_ {
        map(
            tuple((
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
            )),
            |(resolution_scope, type_name, type_namespace)| TypeRef {
                resolution_scope,
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], TypeDef> + '_ {
        map(
            tuple((
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
            )),
            |(flags, name, namespace, extends, _field_list, method_list)| {
                TypeDef {
                    flags,
                    name: name.and_then(|v| {
                        if v.is_empty() {
                            None
                        } else {
                            Some(v)
                        }
                    }),
                    // The namespace can be an empty string (""),
                    namespace: namespace.and_then(|v| {
                        if v.is_empty() {
                            None
                        } else {
                            Some(v)
                        }
                    }),
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                // flags
                le_u16,
                // name (index into the `#String` heap)
                self.string_index(),
                // signature (index into the `#Blob` heap)
                self.blob_index(),
            )),
            |_| (),
        )
    }

    /// Parse MethodDef row.
    ///
    /// ECMA-335 Section II.22.26.
    fn parse_method_def_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], MethodDef> + '_ {
        map(
            tuple((
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
            )),
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Param<'a>> + '_ {
        map(
            tuple((
                le_u16, // flags
                le_u16, // sequence
                // name
                map(self.string_index(), |index| self.get_string(index)),
            )),
            |(_flags, _sequence, name)| Param { name },
        )
    }

    /// Parse InterfaceImpl row.
    ///
    /// ECMA-335 Section II.22.23.
    fn parse_interface_impl_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], InterfaceImpl> + '_ {
        map(
            tuple((
                self.table_index(Table::TypeDef), // class
                self.coded_index(Table::TYPE_DEF_OR_REF), // interface
            )),
            |(class, interface)| InterfaceImpl { class, interface },
        )
    }

    /// Parse MemberRef row.
    ///
    /// ECMA-335 Section II.22.25.
    fn parse_member_ref_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], MemberRef> + '_ {
        map(
            tuple((
                // class
                self.coded_index(&[
                    Table::TypeDef,
                    Table::TypeRef,
                    Table::ModuleRef,
                    Table::MethodDef,
                    Table::TypeSpec,
                ]),
                // name
                map(self.string_index(), |index| self.get_string(index)),
                // signature
                map(self.blob_index(), |index| self.get_blob(index)),
            )),
            |(class, name, signature)| MemberRef { class, name, signature },
        )
    }

    /// Parse Constant row.
    ///
    /// ECMA-335 Section II.22.9.
    fn parse_constant_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Constant> + '_ {
        map(
            tuple((
                map_opt(u8, num::FromPrimitive::from_u8), // type
                u8,                                       // padding
                self.coded_index(&[
                    Table::Field,
                    Table::Param,
                    Table::Property,
                ]),
                map(self.blob_index(), |index| self.get_blob(index)), // value
            )),
            |(type_, _, _, value)| Constant { type_, value },
        )
    }

    /// Parse CustomAttribute row.
    ///
    /// ECMA-335 Section II.22.10.
    fn parse_custom_attribute_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], CustomAttribute> + '_ {
        map(
            tuple((
                // parent
                self.coded_index(Table::HAS_CUSTOM_ATTRIBUTE),
                // type
                self.coded_index(Table::CUSTOM_ATTRIBUTE_TYPE),
                // value
                map(self.blob_index(), |index| self.get_blob(index)),
            )),
            |(parent, type_, value)| CustomAttribute { parent, type_, value },
        )
    }

    /// Parse FieldMarshall row.
    ///
    /// ECMA-335 Section II.22.17.
    fn parse_field_marshal_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                // parent
                self.coded_index(&[Table::Field, Table::Param]),
                // native type (index into blob heap)
                self.blob_index(),
            )),
            |_| (),
        )
    }

    /// Parse DeclSecurity row.
    ///
    /// ECMA-335 Section II.22.11.
    fn parse_decl_security_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
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
            )),
            |_| (),
        )
    }

    /// Parse ClassLayout row.
    ///
    /// ECMA-335 Section II.22.8.
    fn parse_class_layout_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u16,                           // packing size
                le_u32,                           // class size
                self.table_index(Table::TypeDef), // parent (index into typedef table)
            )),
            |_| (),
        )
    }

    /// Parse FieldLayout row.
    ///
    /// ECMA-335 Section II.22.16.
    fn parse_field_layout_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u32,                         // offset
                self.table_index(Table::Field), // field (index into field table)
            )),
            |_| (),
        )
    }

    /// Parse EventMap row.
    ///
    /// ECMA-335 Section II.22.12.
    fn parse_event_map_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                self.table_index(Table::TypeDef), // parent
                self.table_index(Table::Event),   // event list
            )),
            |_| (),
        )
    }

    /// Parse Event row.
    ///
    /// ECMA-335 Section II.22.13.
    fn parse_event_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u16,
                self.string_index(),
                self.coded_index(Table::TYPE_DEF_OR_REF),
            )),
            |_| (),
        )
    }

    /// Parse PropertyMap row.
    ///
    /// ECMA-335 Section II.22.35.
    fn parse_property_map_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                self.table_index(Table::TypeDef),  // parent
                self.table_index(Table::Property), // event list
            )),
            |_| (),
        )
    }

    /// Parse Property row.
    ///
    /// ECMA-335 Section II.22.34.
    fn parse_property_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u16,              // flags
                self.string_index(), // name
                self.blob_index(),   // type
            )),
            |_| (),
        )
    }

    /// Parse MethodSemantics row.
    ///
    /// ECMA-335 Section II.22.28.
    fn parse_method_semantics_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u16, // semantics
                self.table_index(Table::MethodDef),
                self.coded_index(&[Table::Event, Table::Property]),
            )),
            |_| (),
        )
    }

    /// Parse MethodImpl row.
    ///
    /// ECMA-335 Section II.22.27.
    fn parse_method_impl_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                self.table_index(Table::TypeDef),
                self.coded_index(Table::METHOD_DEF_OR_REF),
                self.coded_index(Table::METHOD_DEF_OR_REF),
            )),
            |_| (),
        )
    }

    /// Parse ImplMap row.
    ///
    /// ECMA-335 Section II.22.22.
    fn parse_impl_map_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u16, // mapping flags
                self.coded_index(&[Table::Field, Table::MethodDef]),
                self.string_index(),
                self.table_index(Table::ModuleRef),
            )),
            |_| (),
        )
    }

    /// Parse FieldRVA row.
    ///
    /// ECMA-335 Section II.22.18.
    fn parse_field_rva_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], u32> + '_ {
        map(
            tuple((
                le_u32, // mapping flags
                self.table_index(Table::Field),
            )),
            |(rva, _)| rva,
        )
    }

    /// Parse Assembly row.
    ///
    /// ECMA-335 Section II.22.2.
    fn parse_assembly_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Assembly> + '_ {
        map(
            tuple((
                le_u32,                                                   // hash_alg
                le_u16,            // major_version
                le_u16,            // minor_version
                le_u16,            // build_number
                le_u16,            // revision
                le_u32,            // flags
                self.blob_index(), // public_key_or_token
                map(self.string_index(), |index| self.get_string(index)), // name
                map(self.string_index(), |index| self.get_string(index)), // culture
            )),
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
                    culture: culture.and_then(|v| {
                        if v.is_empty() {
                            None
                        } else {
                            Some(v)
                        }
                    }),
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], AssemblyRef> + '_ {
        map(
            tuple((
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
            )),
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
                public_key_or_token: public_key_or_token.and_then(|v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v)
                    }
                }),
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(tuple((le_u32, self.table_index(Table::AssemblyRef))), |_| ())
    }

    /// Parse AssemblyRefOs row.
    ///
    /// ECMA-335 Section II.22.6.
    fn parse_assembly_ref_os_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u32, // os_platform_id
                le_u32, // os_major_version
                le_u32, // os_minor_version
                self.table_index(Table::AssemblyRef),
            )),
            |_| (),
        )
    }

    /// Parse File row.
    ///
    /// ECMA-335 Section II.22.19.
    fn parse_file_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u32,              // flags
                self.string_index(), // name
                self.blob_index(),   // hash_value
            )),
            |_| (),
        )
    }

    /// Parse ExportedType row.
    ///
    /// ECMA-335 Section II.22.14.
    fn parse_exported_type_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                le_u32,              // flags
                le_u32,              // type_def_if
                self.string_index(), // type_name
                self.string_index(), // type_namespace
                self.coded_index(&[
                    Table::File,
                    Table::AssemblyRef,
                    Table::ExportedType,
                ]),
            )),
            |_| (),
        )
    }

    /// Parse ManifestResource row.
    ///
    /// ECMA-335 Section II.22.24.
    fn parse_manifest_resource_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Resource<'a>> + '_ {
        map(
            tuple((
                le_u32,                                                   // offset
                le_u32, // flags
                map(self.string_index(), |index| self.get_string(index)), // name
                self.coded_index(&[
                    Table::File,
                    Table::AssemblyRef,
                    Table::Null,
                ]),
            )),
            |(offset, _, name, _)| {
                if self.raw_resources.is_none() {
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], NestedClass> + '_ {
        map(
            tuple((
                self.table_index(Table::TypeDef), // nested_class
                self.table_index(Table::TypeDef), // enclosing_class
            )),
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
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], GenericParam> + '_ {
        map(
            tuple((
                le_u16, // number
                le_u16, // flags
                // owner
                self.coded_index(Table::TYPE_OR_METHOD_DEF),
                // name
                map(self.string_index(), |index| self.get_string(index)),
            )),
            |(_number, _flags, owner, name)| GenericParam { owner, name },
        )
    }

    /// Parse MethodSpec row.
    ///
    /// ECMA-335 Section II.22.29.
    fn parse_method_spec_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                self.coded_index(Table::METHOD_DEF_OR_REF), // method
                self.blob_index(),                          // instantiation
            )),
            |_| (),
        )
    }

    /// Parse GenericParamConstraint row.
    ///
    /// ECMA-335 Section II.22.21.
    fn parse_generic_param_constraint_row(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], ()> + '_ {
        map(
            tuple((
                self.table_index(Table::GenericParam),
                self.coded_index(Table::TYPE_DEF_OR_REF),
            )),
            |_| (),
        )
    }
}

/// CLIHeader
///
/// ECMA-335 Section II.25.3.3
struct CLIHeader {
    major_runtime_version: u16,
    minor_runtime_version: u16,
    metadata: DirEntry,
    flags: u32,
    entry_point_token: u32,
    resources: DirEntry,
    strong_name_signature: DirEntry,
}

/// CLIMetadata
///
/// ECMA-335 Section II.24.2.1
struct CLIMetadata<'a> {
    major_version: u16,
    minor_version: u16,
    stream_headers: Vec<StreamHeader<'a>>,
    version: &'a [u8],
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
    fn new(tables: &[Table], index: usize) -> Self {
        let tag_size = f64::log2(tables.len() as f64).ceil() as u32;
        let table_index = index & ((1 << tag_size) - 1);
        let table = tables[table_index];
        let index = index >> tag_size;

        // Indexes in are 1-based, but here we make them 0-based, so that
        // we can use them as Rust vector indexes.
        let index = index.saturating_sub(1);

        Self { table, index }
    }
}

#[derive(Debug)]
struct TypeRef<'a> {
    resolution_scope: CodedIndex,
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
pub struct MemberRef<'a> {
    class: CodedIndex,
    name: Option<&'a str>,
    signature: Option<&'a [u8]>,
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
    name: &'a str,
    full_name: Option<String>,
    base_types: Vec<String>,
    visibility: Visibility,
    semantics: ClassSemantics,
    is_abstract: bool,
    is_sealed: bool,
    methods: Vec<Method<'a>>,
}

#[derive(Debug)]
pub struct Method<'a> {
    name: &'a str,
    parameters: Vec<MethodParam<'a>>,
    return_type: Option<String>,
    visibility: Visibility,
    is_abstract: bool,
    is_static: bool,
    is_virtual: bool,
    is_final: bool,
}

#[derive(Debug)]
pub struct MethodParam<'a> {
    name: Option<&'a str>,
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
        result.set_version(dotnet.version.to_vec());
        result.guids.extend(dotnet.get_guids().map(|guid| guid.to_string()));
        result.module_name = dotnet.modules.first().map(|s| s.to_string());

        result.assembly = dotnet
            .assemblies
            .first()
            .map(protos::dotnet::Assembly::from)
            .into();

        result.assembly_refs.extend(
            dotnet.assembly_refs.iter().map(protos::dotnet::AssemblyRef::from),
        );

        result.streams.extend(
            dotnet.stream_headers.iter().map(protos::dotnet::Stream::from),
        );

        result.resources.extend(
            dotnet.resources.iter().map(protos::dotnet::Resource::from),
        );

        result
            .classes
            .extend(dotnet.get_user_types().map(protos::dotnet::Class::from));

        result
            .constants
            .extend(dotnet.get_string_constants().map(|c| c.to_vec()));

        result.set_number_of_streams(result.streams.len().try_into().unwrap());
        result.set_number_of_guids(result.guids.len().try_into().unwrap());
        result.set_number_of_classes(result.classes.len().try_into().unwrap());

        result.set_number_of_assembly_refs(
            result.assembly_refs.len().try_into().unwrap(),
        );

        result.set_number_of_resources(
            result.resources.len().try_into().unwrap(),
        );

        result.set_number_of_constants(
            result.constants.len().try_into().unwrap(),
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

impl From<&Class<'_>> for protos::dotnet::Class {
    fn from(value: &Class<'_>) -> Self {
        let mut class = protos::dotnet::Class::new();
        class.fullname = value.full_name.clone();
        if let Some(fullname) = &value.full_name {
            if let Some((namespace, name)) = fullname.rsplit_once('.') {
                class.set_namespace(namespace.to_string());
                class.set_name(name.to_string());
            } else {
                class.set_name(fullname.to_string());
            }
        }
        class.set_type(value.semantics.to_string());
        class.base_types = value.base_types.clone();
        class.set_sealed(value.is_sealed);
        class.set_abstract(value.is_abstract);
        class.set_visibility(value.visibility.to_string());
        class
            .methods
            .extend(value.methods.iter().map(protos::dotnet::Method::from));

        class.set_number_of_methods(class.methods.len().try_into().unwrap());
        class.set_number_of_base_types(
            class.base_types.len().try_into().unwrap(),
        );

        class
    }
}

impl From<&Method<'_>> for protos::dotnet::Method {
    fn from(value: &Method<'_>) -> Self {
        let mut method = protos::dotnet::Method::new();
        method.set_name(value.name.to_string());
        method.set_visibility(value.visibility.to_string());
        method.set_abstract(value.is_abstract);
        method.set_virtual(value.is_virtual);
        method.set_final(value.is_final);
        method.set_static(value.is_static);
        method
            .parameters
            .extend(value.parameters.iter().map(protos::dotnet::Param::from));

        method.set_number_of_parameters(
            method.parameters.len().try_into().unwrap(),
        );

        method.return_type = value.return_type.clone();
        method
    }
}

impl From<&MethodParam<'_>> for protos::dotnet::Param {
    fn from(value: &MethodParam<'_>) -> Self {
        let mut param = protos::dotnet::Param::new();
        param.name = value.name.map(|n| n.to_string());
        param.type_ = value.type_.clone();
        param
    }
}

/// Parses a variable-length integer.
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
fn varint(input: &[u8]) -> IResult<&[u8], usize> {
    let (remainder, (_, value)) =
        bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(alt((
            bits_tag(0b0, 1u8).and(bits_take(7u8)),
            bits_tag(0b10, 2u8).and(bits_take(14u8)),
            bits_tag(0b110, 3u8).and(bits_take(29u8)),
        )))(input)?;

    Ok((remainder, value))
}

#[cfg(test)]
mod test {
    #[test]
    fn varint() {
        assert_eq!(
            super::varint(&[0x00, 0x00]).unwrap(),
            ([0x00_u8].as_slice(), 0_usize)
        );

        assert_eq!(
            super::varint(&[0x01, 0x00]).unwrap(),
            ([0x00_u8].as_slice(), 1_usize)
        );

        assert_eq!(
            super::varint(&[0x7F, 0x00]).unwrap(),
            ([0x00_u8].as_slice(), 0x7F_usize)
        );

        assert_eq!(
            super::varint(&[0x8A, 0x00]).unwrap(),
            ([].as_slice(), 0x0A00_usize)
        );

        assert_eq!(
            super::varint(&[0xC1, 0x02, 0x03, 0x04]).unwrap(),
            ([].as_slice(), 0x01020304_usize)
        );

        assert_eq!(
            super::varint(&[0xDF, 0xFF, 0xFF, 0xFF]).unwrap(),
            ([].as_slice(), 0x1FFFFFFF_usize)
        );
    }
}
