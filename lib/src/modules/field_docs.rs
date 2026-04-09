// File generated automatically by build.rs. Do not edit.

pub const FIELD_DOCS: &[(&str, u64, &str)] = &[
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
    ("pe.Version", 2, "Minor version."),
    ("test_proto2.TestProto2", 350, "This field will be visible in YARA as `bool_yara` instead of `bool_proto`."),
    ("test_proto2.TestProto2", 351, "This field won't be visible to YARA."),
    ("test_proto2.TestProto2", 500, "This field is accessible only if the features \"foo\" (or \"FOO\") and \"bar\"
 are enabled while compiling the YARA rules."),
    ("test_proto2.TestProto2", 502, "The metadata received by the module is copied into this field."),
];
