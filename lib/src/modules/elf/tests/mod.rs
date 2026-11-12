use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn import_md5() {
    let elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    rule_true!(
        r#"
        import "elf"
        rule test {
          condition:
            elf.import_md5() == "141ad500037085bdbe4665241c44f936"
        }
        "#,
        &elf
    );
}

#[test]
fn telfhash_does_not_pollute_import_md5_cache() {
    let elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    rule_true!(
        r#"
        import "elf"
        rule test {
          condition:
            elf.telfhash() == "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA" and
            elf.import_md5() == "141ad500037085bdbe4665241c44f936"
        }
        "#,
        &elf
    );
}

#[test]
fn telfhash() {
    let elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    rule_true!(
        r#"
        import "elf"
        rule test {
          condition:
            elf.telfhash() == "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA"
        }
        "#,
        &elf
    );
}

#[test]
fn machines() {
    let mut elf = create_binary_from_zipped_ihex(
        "src/modules/elf/tests/testdata/8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip",
    );

    let machines: &[(&str, u16)] = &[
        ("EM_PARISC", 15),
        ("EM_SPARC32PLUS", 18),
        ("EM_S390", 22),
        ("EM_MCORE", 39),
        ("EM_RCE", 39),
        ("EM_SH", 42),
        ("EM_SPARCV9", 43),
        ("EM_ARC_COMPACT", 93),
        ("EM_BPF", 247),
        ("EM_LOONGARCH", 258),
    ];

    for (name, value) in machines {
        // e_machine sits at offset 18 and the test ELF is little-endian.
        elf[18..20].copy_from_slice(&value.to_le_bytes());

        let rule = format!(
            r#"import "elf" rule test {{ condition: elf.machine == elf.{name} and elf.machine == {value} }}"#
        );

        rule_true!(rule.as_str(), &elf);
    }
}

#[allow(clippy::too_many_arguments)]
fn push_elf32_ehdr(
    buf: &mut Vec<u8>,
    ph_offset: u32,
    ph_count: u16,
    sh_offset: u32,
    sh_count: u16,
    shstrndx: u16,
) {
    buf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
    buf.extend_from_slice(&[0u8; 8]);
    buf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf.extend_from_slice(&3u16.to_le_bytes()); // EM_386
    buf.extend_from_slice(&1u32.to_le_bytes()); // version
    buf.extend_from_slice(&0u32.to_le_bytes()); // entry
    buf.extend_from_slice(&ph_offset.to_le_bytes());
    buf.extend_from_slice(&sh_offset.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&52u16.to_le_bytes()); // ehsize
    buf.extend_from_slice(&32u16.to_le_bytes()); // phentsize
    buf.extend_from_slice(&ph_count.to_le_bytes());
    buf.extend_from_slice(&40u16.to_le_bytes()); // shentsize
    buf.extend_from_slice(&sh_count.to_le_bytes());
    buf.extend_from_slice(&shstrndx.to_le_bytes());
}

fn push_elf32_phdr(buf: &mut Vec<u8>, p_type: u32, offset: u32, filesz: u32) {
    buf.extend_from_slice(&p_type.to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // vaddr
    buf.extend_from_slice(&0u32.to_le_bytes()); // paddr
    buf.extend_from_slice(&filesz.to_le_bytes());
    buf.extend_from_slice(&filesz.to_le_bytes()); // memsz
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0u32.to_le_bytes()); // align
}

fn push_elf32_shdr(
    buf: &mut Vec<u8>,
    name: u32,
    sh_type: u32,
    offset: u32,
    size: u32,
    link: u32,
) {
    buf.extend_from_slice(&name.to_le_bytes());
    buf.extend_from_slice(&sh_type.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0u32.to_le_bytes()); // addr
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&link.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // info
    buf.extend_from_slice(&0u32.to_le_bytes()); // addralign
    buf.extend_from_slice(&0u32.to_le_bytes()); // entsize
}

fn push_elf32_sym(buf: &mut Vec<u8>, name: u32) {
    buf.extend_from_slice(&name.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // value
    buf.extend_from_slice(&0u32.to_le_bytes()); // size
    buf.push(0); // info
    buf.push(0); // other
    buf.extend_from_slice(&0u16.to_le_bytes()); // shndx
}

#[test]
fn name_caps_and_cumulative_budget() {
    use crate::modules::elf::parser::ElfParser;

    // 9,000 symbols all pointing to the same unterminated 8 KiB string:
    // each symbol name is capped to MAX_SYM_NAME_LEN (4 KiB), and cumulative
    // cloned bytes stop once MAX_TOTAL_NAME_BYTES (32 MiB = 8,192 * 4 KiB)
    // is reached.
    let num_syms = 9_000usize;
    let sh_offset = 52u32;
    let sh_count = 3u16; // shstrtab, strtab, symtab
    let strtab_offset = sh_offset + (sh_count as u32) * 40;
    let strtab_len = 8192u32;
    let symtab_offset = strtab_offset + strtab_len;
    let symtab_size = (num_syms * 16) as u32;

    let mut elf = Vec::new();
    push_elf32_ehdr(&mut elf, 0, 0, sh_offset, sh_count, 0);
    // Section 0: .shstrtab pointing at unterminated strtab (tests section cap)
    push_elf32_shdr(&mut elf, 0, 3, strtab_offset, strtab_len, 0);
    // Section 1: .strtab
    push_elf32_shdr(&mut elf, 0, 3, strtab_offset, strtab_len, 0);
    // Section 2: .symtab (linked to section 1)
    push_elf32_shdr(&mut elf, 0, 2, symtab_offset, symtab_size, 1);

    elf.resize(elf.len() + strtab_len as usize, b'A');
    for _ in 0..num_syms {
        push_elf32_sym(&mut elf, 0);
    }

    let parsed = ElfParser::new().parse(&elf).unwrap();

    assert_eq!(parsed.sections.len(), 3);
    for sec in &parsed.sections {
        assert_eq!(
            sec.name.as_ref().map(String::len),
            Some(ElfParser::MAX_SECTION_NAME_LEN)
        );
    }

    assert_eq!(parsed.symtab.len(), num_syms);
    for sym in &parsed.symtab {
        if let Some(name) = &sym.name {
            assert_eq!(name.len(), ElfParser::MAX_SYM_NAME_LEN);
        }
    }

    let named_syms = parsed.symtab.iter().filter(|s| s.name.is_some()).count();
    assert!(named_syms > 0 && named_syms < num_syms);

    let total_bytes: usize = parsed
        .sections
        .iter()
        .filter_map(|s| s.name.as_ref())
        .chain(parsed.symtab.iter().filter_map(|s| s.name.as_ref()))
        .map(String::len)
        .sum();
    assert!(
        total_bytes
            <= ElfParser::MAX_TOTAL_NAME_BYTES + ElfParser::MAX_SYM_NAME_LEN
    );
}

#[test]
fn pt_dynamic_cap() {
    use crate::modules::elf::parser::ElfParser;

    // Multiple PT_DYNAMIC segments pointing to the same dynamic entries and
    // a segment without DT_NULL must be bounded in total by MAX_DYNAMIC_ENTRIES.
    let ph_offset = 52u32;
    let ph_count = 3u16;
    let dyn_offset = ph_offset + (ph_count as u32) * 32;
    let dyn_entries = ElfParser::MAX_DYNAMIC_ENTRIES / 2 + 500;
    let dyn_bytes = (dyn_entries * 8) as u32;

    let mut elf = Vec::new();
    push_elf32_ehdr(&mut elf, ph_offset, ph_count, 0, 0, 0);
    for _ in 0..ph_count {
        push_elf32_phdr(&mut elf, 2, dyn_offset, dyn_bytes);
    }

    for i in 0..dyn_entries {
        elf.extend_from_slice(&1u32.to_le_bytes());
        elf.extend_from_slice(&(i as u32).to_le_bytes());
    }

    let parsed = ElfParser::new().parse(&elf).unwrap();
    assert_eq!(parsed.dynamic.len(), ElfParser::MAX_DYNAMIC_ENTRIES);
    assert_eq!(
        parsed.dynamic_section_entries,
        Some(ElfParser::MAX_DYNAMIC_ENTRIES as i64)
    );
}
