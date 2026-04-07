// File generated automatically by build.rs. Do not edit.

pub const FIELD_DOCS: &[(&str, u64, &str)] = &[
    ("crx.CrxFileHeader", 2, "PSS signature with RSA public key. The public key is formatted as a
 X.509 SubjectPublicKeyInfo block, as in CRX₂. In the common case of a
 developer key proof, the first 128 bits of the SHA-256 hash of the
 public key must equal the crx_id."),
    ("crx.CrxFileHeader", 3, "ECDSA signature, using the NIST P-256 curve. Public key appears in
 named-curve format.
 The pinned algorithm will be this, at least on 2017-01-01."),
    ("crx.CrxFileHeader", 10000, "The binary form of a SignedData message. We do not use a nested
 SignedData message, as handlers of this message must verify the proofs
 on exactly these bytes, so it is convenient to parse in two steps.

 All proofs in this CrxFile message are on the value
 \"CRX3 SignedData\x00\" + signed_header_size + signed_header_data +
 archive, where \"\x00\" indicates an octet with value 0, \"CRX3 SignedData\"
 is encoded using UTF-8, signed_header_size is the size in octets of the
 contents of this field and is encoded using 4 octets in little-endian
 order, signed_header_data is exactly the content of this field, and
 archive is the remaining contents of the file following the header."),
    ("crx.SignedData", 1, "This is simple binary, not UTF-8 encoded mpdecimal; i.e. it is exactly
 16 bytes long."),
    ("dex.DexHeader", 2, "DEX version (35, 36, 37, ...)"),
    ("lnk.Lnk", 1, "True if the file is a LNK file."),
    ("lnk.Lnk", 2, "A description of the shortcut that is displayed to end users to identify
 the purpose of the link."),
    ("lnk.Lnk", 3, "Time when the LNK file was created."),
    ("lnk.Lnk", 4, "Time when the LNK file was last accessed."),
    ("lnk.Lnk", 5, "Time when the LNK files was last modified."),
    ("lnk.Lnk", 6, "Size of the target file in bytes. The target file is the file that this
 link references to. If the link target file is larger than 0xFFFFFFFF,
 this value specifies the least significant 32 bits of the link target file
 size."),
    ("lnk.Lnk", 7, "Attributes of the link target file."),
    ("lnk.Lnk", 8, "Location where the icon associated to the link is found. This is usually
 an EXE or DLL file that contains the icon among its resources. The
 specific icon to be used is indicated by the `icon_index` field."),
    ("lnk.Lnk", 9, "Index of the icon that is associated to the link, within an icon location."),
    ("lnk.Lnk", 10, "Expected window state of an application launched by this link."),
    ("lnk.Lnk", 11, "Type of drive the link is stored on."),
    ("lnk.Lnk", 12, "Drive serial number of the volume the link target is stored on."),
    ("lnk.Lnk", 13, "Volume label of the drive the link target is stored on."),
    ("lnk.Lnk", 14, "String used to construct the full path to the link target by appending the
 common_path_suffix field."),
    ("lnk.Lnk", 15, "String used to construct the full path to the link target by being appended
 to the local_base_path field."),
    ("lnk.Lnk", 16, "Location of the link target relative to the LNK file."),
    ("lnk.Lnk", 17, "Path of the working directory to be used when activating the link target."),
    ("lnk.Lnk", 18, "Command-line arguments that are specified when activating the link target."),
    ("lnk.Lnk", 19, "Size in bytes of any extra data appended to the LNK file."),
    ("lnk.Lnk", 20, "Offset within the LNK file where the overlay starts."),
    ("lnk.Lnk", 21, "Distributed link tracker information."),
    ("macho.Macho", 1, "Set Mach-O header and basic fields"),
    ("macho.Macho", 29, "Add fields for Mach-O fat binary header"),
    ("macho.Macho", 32, "Nested Mach-O files"),
    ("pe.PE", 16, "Entry point as a file offset."),
    ("pe.PE", 17, "Entry point as it appears in the PE header (RVA)."),
    ("pe.PE", 53, "TODO: implement resource_version?"),
    ("pe.Section", 1, "The section's name as listed in the section table. The data type is `bytes`
 instead of `string` so that it can accommodate invalid UTF-8 content. The
 length is 8 bytes at most."),
    ("pe.Section", 2, "For section names longer than 8 bytes, the name in the section table (and
 in the `name` field) contains a forward slash (/) followed by an ASCII
 representation of a decimal number that is an offset into the string table.
 (examples: \"/4\", \"/123\") This mechanism is described in the MSDN and used
 by GNU compilers.

 When this scenario occurs, the `full_name` field holds the actual section
 name. In all other cases, it simply duplicates the content of the `name`
 field.

 See: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header#members"),
    ("pe.Version", 1, "Major version."),
    ("test_proto2.TestProto2", 350, "This field will be visible in YARA as `bool_yara` instead of `bool_proto`."),
    ("test_proto2.TestProto2", 351, "This field won't be visible to YARA."),
    ("test_proto2.TestProto2", 500, "This field is accessible only if the features \"foo\" (or \"FOO\") and \"bar\"
 are enabled while compiling the YARA rules."),
    ("test_proto2.TestProto2", 502, "The metadata received by the module is copied into this field."),
    ("yara.FieldOptions", 1, "Name of the field in YARA rules.

 By default, the name of the field in YARA rules is the same it has in
 the protobuf, but sometimes it's useful to override this behaviour and
 specify our own name. For instance, suppose we have the following field
 definition:

 FileMetadata metadata = 32 [(yara.field_options).name = \"meta\"];

 The name of the field in the protobuf is \"metadata\", but this is a
 reserved keyword in YARA, so we use (yara.field_options).name = \"meta\"
 for specifying a different name."),
    ("yara.FieldOptions", 2, "Ignore the field and don't use it in YARA.

 This is useful when the protobuf definition has some fields that we don't
 want to expose to YARA rules. For example:

 string some_private_data = 32 [(yara.field_options).ignore = true];"),
    ("yara.FieldOptions", 3, "Control under which circumstances the field is accessible by YARA rules.

 In some cases, a field should only be used in YARA rules when certain
 requirements are satisfied. Consider the following field definition:

 uint64 my_field = 1 [
   (yara.field_options) = {
     acl: [
       {
         accept_if: [\"foo\", \"FOO\"],
         error_title: \"foo is required\",
         error_label: \"this field was used without foo\"
       },
       {
         accept_if: \"bar\",
         error_title: \"bar is required\",
         error_label: \"this field was used without bar\"
       },
       {
         reject_if: \"baz\",
         error_title: \"baz is forbidden\",
         error_label: \"this field was used with baz\"
       }
     ]
   }
 ];

 The field \"my_field\" can be used in YARA rules, but only if the features
 \"foo\" (or \"FOO\") and \"bar\" are enabled in the YARA compiler, while \"baz\"
 must not be enabled. If these conditions are not met, the compiler will
 return an error. For example, if \"FOO\" and \"baz\" are enabled, the following
 error will occur:

 error[E034]: bar is required
  --> line:5:29
   |
 5 |  my_module.my_field == 0
   |            ^^^^^^^^ this field was used without bar
   |

 Notice that the error message's title and label are derived from the ACL
 entry that was not satisfied.

 Also, keep in mind that ACL entries are evaluated sequentially. The first
 entry that fails will trigger the corresponding error message."),
    ("yara.FieldOptions", 4, "Indicates that a string field is always lowercase.

 This option can be used only with fields of type string. If used with some
 other type YARA will panic.

 string some_lowercase_string = 32 [(yara.field_options).lowercase = true];"),
    ("yara.FieldOptions", 5, "Specifies the format of the field when converted to a string.

 This option can be used with integer, float, and boolean fields. It uses
 Rust's formatting syntax. For example, if an integer field has `fmt = \"{:#x}\"`
 it will be formatted as a hexadecimal string with a \"0x\" prefix."),
    ("yara.FieldOptions", 6, "Indicates that the field is deprecated.

 This option is used for indicating that a field is deprecated."),
];
