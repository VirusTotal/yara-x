use pretty_assertions::assert_eq;

use crate::modules::macho::*;
use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_false;
use crate::tests::rule_true;
use crate::tests::test_rule;

fn create_test_macho_file() -> File {
    File {
        magic: Some(MH_MAGIC),
        number_of_segments: Some(2),
        segments: vec![
            Segment {
                vmaddr: Some(0x1000),
                vmsize: Some(0x1000),
                fileoff: Some(0x400),
                filesize: Some(0x1000),
                ..Default::default()
            },
            Segment {
                vmaddr: Some(0x2000),
                vmsize: Some(0x1000),
                fileoff: Some(0x1400),
                filesize: Some(0x1000),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[test]
fn test_parse_magic() {
    let test_cases = [
        (MH_MAGIC, &[206, 250, 237, 254]),
        (MH_CIGAM, &[254, 237, 250, 206]),
        (MH_MAGIC_64, &[207, 250, 237, 254]),
        (MH_CIGAM_64, &[254, 237, 250, 207]),
        (FAT_MAGIC, &[190, 186, 254, 202]),
        (FAT_CIGAM, &[202, 254, 186, 190]),
        (FAT_MAGIC_64, &[191, 186, 254, 202]),
        (FAT_CIGAM_64, &[202, 254, 186, 191]),
    ];

    for (magic_val, input) in test_cases {
        let result = parse_magic(input);
        assert_eq!(result, Ok((&[] as &[u8], magic_val)));
    }

    // Invalid input (short)
    let short_input = &[206, 250];
    let result = parse_magic(short_input);
    assert!(result.is_err());

    // Not a Mach-O magic constant, parsing should still succeed
    let input = &[99, 99, 99, 99];
    let result = parse_magic(input);
    assert!(result.is_ok());
}

#[test]
fn test_is_macho_file_block() {
    // Valid data
    let valid_file_blocks = [
        (MH_MAGIC, &[206, 250, 237, 254]),
        (MH_CIGAM, &[254, 237, 250, 206]),
        (MH_MAGIC_64, &[207, 250, 237, 254]),
        (MH_CIGAM_64, &[254, 237, 250, 207]),
    ];

    for (_, valid_file_block) in valid_file_blocks {
        assert_eq!(is_macho_file_block(valid_file_block), true);
    }

    // Invalid data - FAT header
    let invalid_file_blocks = [
        (FAT_MAGIC, &[190, 186, 254, 202]),
        (FAT_CIGAM, &[202, 254, 186, 190]),
        (FAT_MAGIC_64, &[191, 186, 254, 202]),
        (FAT_CIGAM_64, &[202, 254, 186, 191]),
    ];

    for (_, valid_file_block) in invalid_file_blocks {
        assert_eq!(is_macho_file_block(valid_file_block), false);
    }

    // Invalid data - not a valid Mach-O header
    assert_eq!(is_macho_file_block(&[99, 99, 99, 99]), false);
}

#[test]
fn test_is_fat_macho_file_block() {
    // Valid data
    let valid_fat_blocks = [
        (FAT_MAGIC, &[190, 186, 254, 202]),
        (FAT_CIGAM, &[202, 254, 186, 190]),
        (FAT_MAGIC_64, &[191, 186, 254, 202]),
        (FAT_CIGAM_64, &[202, 254, 186, 191]),
    ];

    for (_, valid_file_block) in valid_fat_blocks {
        assert_eq!(is_fat_macho_file_block(valid_file_block), true);
    }

    // Invalid data - file blocks
    let valid_file_blocks = [
        (MH_MAGIC, &[206, 250, 237, 254]),
        (MH_CIGAM, &[254, 237, 250, 206]),
        (MH_MAGIC_64, &[207, 250, 237, 254]),
        (MH_CIGAM_64, &[254, 237, 250, 207]),
    ];

    for (_, valid_file_block) in valid_file_blocks {
        assert_eq!(is_fat_macho_file_block(valid_file_block), false);
    }
}

#[test]
fn test_is_32_bit() {
    assert_eq!(is_32_bit(MH_MAGIC), true);
    assert_eq!(is_32_bit(MH_CIGAM), true);
    assert_eq!(is_32_bit(MH_MAGIC_64), false);
    assert_eq!(is_32_bit(MH_CIGAM_64), false);
}

#[test]
fn test_fat_is_32() {
    assert_eq!(fat_is_32(FAT_MAGIC), true);
    assert_eq!(fat_is_32(FAT_CIGAM), true);
    assert_eq!(fat_is_32(FAT_MAGIC_64), false);
    assert_eq!(fat_is_32(FAT_CIGAM_64), false);
}

#[test]
fn test_should_swap_bytes() {
    assert_eq!(should_swap_bytes(MH_CIGAM), true);
    assert_eq!(should_swap_bytes(MH_CIGAM_64), true);
    assert_eq!(should_swap_bytes(FAT_CIGAM), true);
    assert_eq!(should_swap_bytes(FAT_CIGAM_64), true);
    assert_eq!(should_swap_bytes(MH_MAGIC), false);
    assert_eq!(should_swap_bytes(MH_MAGIC_64), false);
    assert_eq!(should_swap_bytes(FAT_MAGIC), false);
    assert_eq!(should_swap_bytes(FAT_MAGIC_64), false);
}

#[test]
fn test_convert_to_version_string() {
    assert_eq!(convert_to_version_string(65536), "1.0.0");
    assert_eq!(convert_to_version_string(102895360), "1570.15.0");
    assert_eq!(convert_to_version_string(0), "0.0.0");
}

#[test]
fn test_rva_to_offset() {
    let macho = create_test_macho_file();

    // Address within segment 1
    let rva = 0x1500;
    assert_eq!(
        macho_rva_to_offset(rva, &macho).unwrap(),
        Some(0x400 + (0x1500 - 0x1000))
    );

    // Address within segment 2
    let rva = 0x2500;
    assert_eq!(
        macho_rva_to_offset(rva, &macho).unwrap(),
        Some(0x1400 + (0x2500 - 0x2000))
    );

    // Address out of range
    let rva = 0x5000;
    assert_eq!(macho_rva_to_offset(rva, &macho).unwrap(), None);
}

#[test]
fn test_offset_to_rva() {
    let macho = create_test_macho_file();

    // Offset within segment 1
    let offset = 0x500;
    assert_eq!(
        macho_offset_to_rva(offset, &macho).unwrap(),
        Some(0x1000 + (0x500 - 0x400))
    );

    // Offset within segment 2
    let offset = 0x1600;
    assert_eq!(
        macho_offset_to_rva(offset, &macho).unwrap(),
        Some(0x2000 + (0x1600 - 0x1400))
    );

    // Offset out of range
    let offset = 0x5000;
    assert_eq!(macho_offset_to_rva(offset, &macho).unwrap(), None);
}

#[test]
fn test_swap_mach_header() {
    let mut header = MachOHeader64 {
        magic: 0x11223344,
        cputype: 0x55667788,
        cpusubtype: 0x99AABBCC,
        filetype: 0xDDDDFFFF,
        ncmds: 0xEEEEEEEE,
        sizeofcmds: 0x11111111,
        flags: 0x22222222,
        reserved: 0x33333333,
    };

    swap_mach_header(&mut header);

    assert_eq!(header.magic, 0x11223344); // Magic value is not swapped
    assert_eq!(header.cputype, 0x88776655);
    assert_eq!(header.cpusubtype, 0xCCBBAA99);
    assert_eq!(header.filetype, 0xFFFFDDDD);
    assert_eq!(header.ncmds, 0xEEEEEEEE);
    assert_eq!(header.sizeofcmds, 0x11111111);
    assert_eq!(header.flags, 0x22222222);
    assert_eq!(header.reserved, 0x33333333);
}

#[test]
fn test_swap_load_command() {
    let mut command = LoadCommand { cmd: 0x11223344, cmdsize: 0x55667788 };

    swap_load_command(&mut command);

    assert_eq!(command.cmd, 0x44332211);
    assert_eq!(command.cmdsize, 0x88776655);
}

#[test]
fn test_swap_dylib() {
    let mut command = DylibObject {
        timestamp: 0x11223344,
        compatibility_version: 0x55667788,
        current_version: 0x99AABBCC,
        ..Default::default()
    };

    swap_dylib(&mut command);

    assert_eq!(command.timestamp, 0x44332211);
    assert_eq!(command.compatibility_version, 0x88776655);
    assert_eq!(command.current_version, 0xCCBBAA99);
}

#[test]
fn test_swap_dylib_command() {
    let mut command = DylibCommand {
        cmd: 0x11223344,
        cmdsize: 0x55667788,
        ..Default::default()
    };

    swap_dylib_command(&mut command);

    assert_eq!(command.cmd, 0x44332211);
    assert_eq!(command.cmdsize, 0x88776655);
}

#[test]
fn test_swap_rpath_command() {
    let mut command = RPathCommand {
        cmd: 0x11223344,
        cmdsize: 0x55667788,
        ..Default::default()
    };

    swap_rpath_command(&mut command);

    assert_eq!(command.cmd, 0x44332211);
    assert_eq!(command.cmdsize, 0x88776655);
}

#[test]
fn test_swap_segment_command() {
    let mut segment = SegmentCommand32 {
        cmd: 0x11223344,
        cmdsize: 0x55667788,
        segname: [0; 16],
        vmaddr: 0x99AABBCC,
        vmsize: 0xDDDDFFFF,
        fileoff: 0xEEEEEEEE,
        filesize: 0x11111111,
        maxprot: 0x22222222,
        initprot: 0x33333333,
        nsects: 0x44444444,
        flags: 0x55555555,
    };

    swap_segment_command(&mut segment);

    assert_eq!(segment.cmd, 0x44332211);
    assert_eq!(segment.cmdsize, 0x88776655);
    assert_eq!(segment.vmaddr, 0xCCBBAA99);
    assert_eq!(segment.vmsize, 0xFFFFDDDD);
    assert_eq!(segment.fileoff, 0xEEEEEEEE);
    assert_eq!(segment.filesize, 0x11111111);
    assert_eq!(segment.maxprot, 0x22222222);
    assert_eq!(segment.initprot, 0x33333333);
    assert_eq!(segment.nsects, 0x44444444);
    assert_eq!(segment.flags, 0x55555555);
}

#[test]
fn test_swap_segment_command_64() {
    let mut segment = SegmentCommand64 {
        cmd: 0x11223344,
        cmdsize: 0x55667788,
        segname: [0; 16],
        vmaddr: 0x99AABBCCDDDDFFFF,
        vmsize: 0x1111111122222222,
        fileoff: 0x3333333344444444,
        filesize: 0x5555555566666666,
        maxprot: 0x77777777,
        initprot: 0x88888888,
        nsects: 0x99999999,
        flags: 0xAAAAAAAA,
    };

    swap_segment_command_64(&mut segment);

    assert_eq!(segment.cmd, 0x44332211);
    assert_eq!(segment.cmdsize, 0x88776655);
    assert_eq!(segment.vmaddr, 0xFFFFDDDDCCBBAA99);
    assert_eq!(segment.vmsize, 0x2222222211111111);
    assert_eq!(segment.fileoff, 0x4444444433333333);
    assert_eq!(segment.filesize, 0x6666666655555555);
    assert_eq!(segment.maxprot, 0x77777777);
    assert_eq!(segment.initprot, 0x88888888);
    assert_eq!(segment.nsects, 0x99999999);
    assert_eq!(segment.flags, 0xAAAAAAAA);
}

#[test]
fn test_swap_segment_section() {
    let mut section = SegmentSection32 {
        sectname: [0; 16],
        segname: [0; 16],
        addr: 0x11223344,
        size: 0x55667788,
        offset: 0x99AABBCC,
        align: 0xDDDDFFFF,
        reloff: 0xEEEEEEEE,
        nreloc: 0x11111111,
        flags: 0x22222222,
        reserved1: 0x33333333,
        reserved2: 0x44444444,
    };

    swap_segment_section(&mut section);

    assert_eq!(section.addr, 0x44332211);
    assert_eq!(section.size, 0x88776655);
    assert_eq!(section.offset, 0xCCBBAA99);
    assert_eq!(section.align, 0xFFFFDDDD);
    assert_eq!(section.reloff, 0xEEEEEEEE);
    assert_eq!(section.nreloc, 0x11111111);
    assert_eq!(section.flags, 0x22222222);
    assert_eq!(section.reserved1, 0x33333333);
    assert_eq!(section.reserved2, 0x44444444);
}

#[test]
fn test_swap_segment_section_64() {
    let mut section = SegmentSection64 {
        sectname: [0; 16],
        segname: [0; 16],
        addr: 0x99AABBCCDDDDFFFF,
        size: 0x1111111122222222,
        offset: 0xCCBBAA99,
        align: 0xFFFFDDDD,
        reloff: 0xEEEEEEEE,
        nreloc: 0x11111111,
        flags: 0xBBBBBBBB,
        reserved1: 0xCCCCCCCC,
        reserved2: 0xDDDDDDDD,
        reserved3: 0xEEEEEEEE,
    };

    swap_segment_section_64(&mut section);

    assert_eq!(section.addr, 0xFFFFDDDDCCBBAA99);
    assert_eq!(section.size, 0x2222222211111111);
    assert_eq!(section.offset, 0x99AABBCC);
    assert_eq!(section.align, 0xDDDDFFFF);
    assert_eq!(section.reloff, 0xEEEEEEEE);
    assert_eq!(section.nreloc, 0x11111111);
    assert_eq!(section.flags, 0xBBBBBBBB);
    assert_eq!(section.reserved1, 0xCCCCCCCC);
    assert_eq!(section.reserved2, 0xDDDDDDDD);
    assert_eq!(section.reserved3, 0xEEEEEEEE);
}

#[test]
fn test_swap_entry_point_command() {
    let mut entry = EntryPointCommand {
        cmd: 0x11223344,
        cmdsize: 0x55667788,
        entryoff: 0x99AABBCCDDDDFFFF,
        stacksize: 0x1111111122222222,
    };

    swap_entry_point_command(&mut entry);

    assert_eq!(entry.cmd, 0x44332211);
    assert_eq!(entry.cmdsize, 0x88776655);
    assert_eq!(entry.entryoff, 0xFFFFDDDDCCBBAA99);
    assert_eq!(entry.stacksize, 0x2222222211111111);
}

#[test]
fn test_macho_module() {
    let macho_data = create_binary_from_zipped_ihex(
        "src/modules/macho/tests/testdata/tiny_universal.in.zip",
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeedface and
            macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
            macho.MH_CIGAM == 0xcefaedfe and
            macho.CPU_TYPE_MIPS == 0x00000008
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeedface and
            macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
            macho.MH_CIGAM == 0xcefaedfe and
            macho.CPU_TYPE_MIPS == 0x00000008
        }
        "#,
        &[]
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.MH_MAGIC == 0xfeeeeeee or
            macho.MH_NO_REEXPORTED_DYLIBS == 0x99999999 or
            macho.MH_CIGAM == 0xaaaaaaaa or
            macho.CPU_TYPE_MIPS == 0x00000000
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000007) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x01000007) == 1
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000008) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x01000008)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000007, 0x00000003) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(16777223, 2147483651) == 1
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.file_index_for_arch(0x00000008, 0x00000004) == 0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x00000008, 0x00000004)
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.file_index_for_arch(0x00000007, 0x00000003)
        }
        "#,
        &[]
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000007) == 0x00001EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x01000007) == 0x00004EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000007, 0x00000003) == 0x00001EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(16777223, 2147483651) == 0x00004EE0
        }
        "#,
        &macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule test {
          condition:
            macho.entry_point_for_arch(0x00000008, 0x00000003) == 0x00001EE0
        }
        "#,
        &macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule test {
          condition:
            not defined macho.entry_point_for_arch(0x00000007, 0x00000003)
        }
        "#,
        &[]
    );
}
