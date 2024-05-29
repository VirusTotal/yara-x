use std::cmp::{max, min};

/// Trait implemented by types that describe a PE section, specifically this
/// trait is implemented by [`crate::modules::protos::pe::Section`] and
/// [`crate::modules::pe::parser::Section`]. Allows a generic implementation
/// of `rva_to_offset` that works for both types.
pub(crate) trait Section {
    fn virtual_address(&self) -> u32;
    fn virtual_size(&self) -> u32;
    fn raw_data_offset(&self) -> u32;
    fn raw_data_size(&self) -> u32;
}

/// Convert a relative virtual address (RVA) to a file offset.
///
/// An RVA is an offset relative to the base address of the executable
/// program. The PE format uses RVAs in multiple places and sometimes
/// is necessary to convert the RVA to a file offset.
pub(crate) fn rva_to_offset(
    rva: u32,
    sections: &[impl Section],
    file_alignment: u32,
    section_alignment: u32,
) -> Option<u32> {
    // Find the RVA for the section with the lowest RVA.
    let lowest_section_rva =
        sections.iter().map(|section| section.virtual_address()).min();

    // The target RVA is lower than the RVA of all sections, in such cases
    // the RVA is directly mapped to a file offset.
    if matches!(lowest_section_rva, Some(x) if rva < x) {
        return Some(rva);
    }

    let mut section_rva = 0;
    let mut section_offset = 0;
    let mut section_raw_size = 0;

    // Find the section that contains the target RVA. If there are multiple
    // sections that may contain the RVA, the last one is used.
    for s in sections.iter() {
        // In theory, we should use the section's virtual size while
        // checking if some RVA is within the section. In most cases
        // the virtual size is greater than the raw data size, but that's
        // not always the case. So we use the larger of the two values.
        //
        // Example:
        // db6a9934570fa98a93a979e7e0e218e0c9710e5a787b18c6948f2eedd9338984
        let size = max(s.virtual_size(), s.raw_data_size());
        let start = s.virtual_address();
        let end = start.saturating_add(size);

        // Check if the target RVA is within the boundaries of this
        // section, but only update `section_rva` with values
        // that are higher than the current one.
        if section_rva <= s.virtual_address() && (start..end).contains(&rva) {
            section_rva = s.virtual_address();
            section_offset = s.raw_data_offset();
            section_raw_size = s.raw_data_size();

            // According to the PE specification, file_alignment should
            // be a power of 2 between 512 and 64KB, inclusive. And the
            // default value is 512 (0x200). But PE files with lower values
            // (like 64, 32, and even 1) do exist in the wild and are
            // correctly handled by the Windows loader. For files with
            // very small values of file_alignment see:
            // http://www.phreedom.org/research/tinype/
            //
            // Also, according to Ero Carreras's pefile.py, file alignments
            // greater than 512, are actually ignored and 512 is used
            // instead.
            let file_alignment = min(file_alignment, 0x200);

            // Round down section_offset to a multiple of file_alignment.
            if let Some(rem) = section_offset.checked_rem(file_alignment) {
                section_offset -= rem;
            }

            if section_alignment >= 0x1000 {
                // Round section_offset down to sector size (512 bytes).
                section_offset =
                    section_offset.saturating_sub(section_offset % 0x200);
            }
        }
    }

    // PE sections can have a raw (on disk) size smaller than their
    // in-memory size. In such cases, even though the RVA lays within
    // the boundaries of the section while in memory, the RVA doesn't
    // have an associated file offset.
    if rva.saturating_sub(section_rva) >= section_raw_size {
        return None;
    }

    let result = section_offset.saturating_add(rva - section_rva);

    // TODO
    // Make sure the resulting offset is within the file.
    //if result as usize >= self.data.len() {
    //    return None;
    //}

    Some(result)
}

impl Section for crate::modules::protos::pe::Section {
    fn virtual_address(&self) -> u32 {
        self.virtual_address.unwrap()
    }

    fn virtual_size(&self) -> u32 {
        self.virtual_size.unwrap()
    }

    fn raw_data_offset(&self) -> u32 {
        self.raw_data_offset.unwrap()
    }

    fn raw_data_size(&self) -> u32 {
        self.raw_data_size.unwrap()
    }
}
