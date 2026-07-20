use indexmap::IndexMap;
use nom::{
    IResult, Parser,
    bytes::complete::take,
    error::{Error as NomError, ErrorKind},
    multi::count,
    number::complete::{le_u16, le_u32},
};
use std::borrow::Cow;

const OLECF_SIGNATURE: &[u8] =
    &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const DIRECTORY_ENTRY_SIZE: u64 = 128;
const MAX_STREAM_SIZE: u64 = 256 * 1024 * 1024;

// Special sectors
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FREESECT: u32 = 0xFFFFFFFF;
const MAX_REGULAR_SECTOR: u32 = 0xFFFFFFFA;

/// Represents the object type of an MS-CFB Directory Entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirEntryType {
    Unknown,
    Storage,
    Stream,
    LockBytes,
    Property,
    RootStorage,
}

impl From<u8> for DirEntryType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Storage,
            2 => Self::Stream,
            3 => Self::LockBytes,
            4 => Self::Property,
            5 => Self::RootStorage,
            _ => Self::Unknown,
        }
    }
}

/// A parser for OLE Compound File Binary Format (MS-CFB) files.
///
/// `Olecf` analyzes file headers, FAT/DIFAT allocation chains, directory
/// entries, and stream contents for OLE compound documents (e.g., DOC, XLS,
/// PPT, MSI).
pub struct Olecf<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    fat_sectors: Vec<u32>,
    directory_sectors: Vec<u32>,
    mini_fat_sectors: Vec<u32>,
    dir_entries: IndexMap<String, DirectoryEntry>,
    mini_stream_start: u32,
    mini_stream_size: u64,
}

/// Represents a single entry in the MS-CFB directory stream.
pub struct DirectoryEntry {
    pub name: String,
    pub size: u64,
    pub start_sector: u32,
    pub stream_type: DirEntryType,
}

impl<'a> Olecf<'a> {
    /// Creates a new `Olecf` from a byte slice and initializes internal
    /// data structures by parsing the file header, FAT/DIFAT tables, and
    /// directory entries.
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut olecf = Olecf {
            data,
            sector_size: 0,
            mini_sector_size: 0,
            mini_stream_start: 0,
            mini_stream_size: 0,
            fat_sectors: Vec::new(),
            directory_sectors: Vec::new(),
            mini_fat_sectors: Vec::new(),
            dir_entries: IndexMap::new(),
        };

        // (A) Check the 8-byte OLECF signature.
        let (input, sig) = take::<_, _, NomError<&[u8]>>(8_usize)
            .parse(data)
            .map_err(|_| "Failed to parse OLECF data")?;

        if sig != OLECF_SIGNATURE {
            return Err("Failed to parse OLECF data");
        }

        // (B) Parse the rest of the header fields.
        let (input, ()) = olecf
            .parse_header(input)
            .map_err(|_| "Failed to parse OLECF data")?;

        // (C) Parse the directory chain.
        olecf
            .parse_directory(input)
            .map_err(|_| "Failed to parse OLECF data")?;

        Ok(olecf)
    }

    /// Parses the MS-CFB header, including sector shifts, FAT/DIFAT sectors,
    /// directory sector chains, and MiniFAT tables.
    fn parse_header(&mut self, input: &'a [u8]) -> IResult<&'a [u8], ()> {
        let (
            mut input,
            (
                _,
                byte_order,
                sector_shift,
                mini_sector_shift,
                _,
                num_fat_sectors,
                first_dir_sector,
                _,
                first_mini_fat,
                mini_fat_count,
                first_difat_sector,
                difat_count,
            ),
        ) = (
            take(20usize), // skip 20 bytes
            le_u16,        // byte_order
            le_u16,        // sector_shift
            le_u16,        // mini_sector_shift
            take(10usize), // skip 10 bytes
            le_u32,        // num_fat_sectors
            le_u32,        // parse first_dir_sector
            take(8usize),  // skip 8 bytes
            le_u32,        // first_mini_fat
            le_u32,        // mini_fat_count
            le_u32,        // first_difat_sector
            le_u32,        // difat_count
        )
            .parse(input)?;

        // (A) Verify `byte_order == 0xFFFE` and valid sector shifts.
        if byte_order != 0xFFFE {
            return Err(nom::Err::Error(NomError::new(
                input,
                ErrorKind::Verify,
            )));
        }

        // sector_size is 2 ^ sector_shift
        match sector_shift {
            // Version 4.
            12 => self.sector_size = 4096,
            // Version 3.
            9 => self.sector_size = 512,
            // Other sector sizes are not valid.
            _ => {
                return Err(nom::Err::Error(NomError::new(
                    input,
                    ErrorKind::Verify,
                )));
            }
        }

        self.mini_sector_size = if (1..=16).contains(&mini_sector_shift) {
            1 << mini_sector_shift
        } else {
            64
        };

        // (B) Parse up to 109 DIFAT entries from `input`
        //     109 is the max allowed number of DIFAT entries in the header.
        let rest = input;
        if rest.len() < 109 * 4 {
            let possible = rest.len() / 4;
            let (rest2, entries) = count(le_u32, possible).parse(rest)?;
            let mut filtered = entries
                .into_iter()
                .filter(|&x| x < MAX_REGULAR_SECTOR)
                .collect::<Vec<_>>();
            self.fat_sectors.append(&mut filtered);
            input = rest2;
        } else {
            let (rest2, entries) = count(le_u32, 109).parse(rest)?;
            let mut filtered = entries
                .into_iter()
                .filter(|&x| x < MAX_REGULAR_SECTOR)
                .collect::<Vec<_>>();
            self.fat_sectors.append(&mut filtered);
            input = rest2;
        }

        // Follow the DIFAT chain if present.
        let mut next_difat_sector = first_difat_sector;
        let entries_per_sector = self.sector_size / 4;

        // Bound fat_sectors to what a file of this size can legitimately need.
        let max_fat_sectors =
            (self.data.len() / self.sector_size / entries_per_sector) + 2;

        let mut visited_difat = std::collections::HashSet::new();

        for _ in 0..difat_count {
            if next_difat_sector >= MAX_REGULAR_SECTOR
                || next_difat_sector == ENDOFCHAIN
            {
                break;
            }

            // Stop if this DIFAT sector was already processed (cycle detection).
            if !visited_difat.insert(next_difat_sector) {
                break;
            }

            let sector_data = match self.read_sector(next_difat_sector) {
                Ok(data) => data,
                Err(_) => break,
            };

            // The first (entries_per_sector - 1) entries point to FAT sectors
            for i in 0..(entries_per_sector - 1) {
                if self.fat_sectors.len() >= max_fat_sectors {
                    break;
                }
                let fat_sec = match parse_u32_at(sector_data, i * 4) {
                    Ok(sec) => sec,
                    Err(_) => break,
                };
                if fat_sec < MAX_REGULAR_SECTOR {
                    self.fat_sectors.push(fat_sec);
                }
            }

            if self.fat_sectors.len() >= max_fat_sectors {
                break;
            }

            // The last entry points to the next DIFAT sector
            next_difat_sector = match parse_u32_at(
                sector_data,
                (entries_per_sector - 1) * 4,
            ) {
                Ok(sec) => sec,
                Err(_) => break,
            };
        }

        // (C) Directory chain
        if first_dir_sector < MAX_REGULAR_SECTOR {
            self.directory_sectors = self.follow_chain(first_dir_sector);
        } else {
            return Err(nom::Err::Error(NomError::new(
                input,
                ErrorKind::Verify,
            )));
        }

        // (D) MiniFAT chain
        if mini_fat_count > 0 && first_mini_fat < MAX_REGULAR_SECTOR {
            self.mini_fat_sectors = self.follow_chain(first_mini_fat);
        }

        // (E) If no FAT sectors but num_fat_sectors != 0 => error
        if self.fat_sectors.is_empty() && num_fat_sectors > 0 {
            return Err(nom::Err::Error(NomError::new(
                input,
                ErrorKind::Verify,
            )));
        }

        Ok((input, ()))
    }

    /// Traverses the directory sector chain and extracts all directory entries,
    /// indexing standard streams and root storage metadata.
    fn parse_directory(&mut self, _input: &'a [u8]) -> IResult<&'a [u8], ()> {
        if self.directory_sectors.is_empty() {
            return Err(nom::Err::Error(NomError::new(
                _input,
                ErrorKind::Verify,
            )));
        }

        for &sector in &self.directory_sectors {
            let mut entry_offset = 0u64;

            while entry_offset + DIRECTORY_ENTRY_SIZE
                <= self.sector_size as u64
            {
                let abs_offset =
                    self.sector_to_offset(sector).saturating_add(entry_offset);

                if abs_offset.saturating_add(DIRECTORY_ENTRY_SIZE)
                    > self.data.len() as u64
                {
                    break;
                }

                if let Ok(entry) =
                    self.read_directory_entry(abs_offset as usize)
                {
                    if entry.stream_type == DirEntryType::RootStorage {
                        self.mini_stream_start = entry.start_sector;
                        self.mini_stream_size = entry.size;
                    }
                    if matches!(
                        entry.stream_type,
                        DirEntryType::Storage
                            | DirEntryType::Stream
                            | DirEntryType::RootStorage
                    ) {
                        let overwrite = match self.dir_entries.get(&entry.name)
                        {
                            Some(existing) => {
                                entry.stream_type == DirEntryType::Stream
                                    || existing.stream_type
                                        != DirEntryType::Stream
                            }
                            None => true,
                        };
                        if overwrite {
                            self.dir_entries.insert(entry.name.clone(), entry);
                        }
                    }
                }
                entry_offset += DIRECTORY_ENTRY_SIZE;
            }
        }

        Ok((_input, ()))
    }

    /// Returns the underlying byte slice.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the sector size in bytes.
    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// Returns `true` if the underlying byte slice starts with a valid 8-byte
    /// OLECF signature (`0xD0CF11E0A1B11AE1`), or `false` otherwise.
    pub fn is_valid_header(&self) -> bool {
        self.data.len() >= OLECF_SIGNATURE.len()
            && &self.data[..OLECF_SIGNATURE.len()] == OLECF_SIGNATURE
    }

    /// Returns a vector containing the names of all streams found in the
    /// directory.
    ///
    /// Returns an error if the directory contains no streams.
    pub fn stream_names(&self) -> Result<Vec<String>, &'static str> {
        if self.dir_entries.is_empty() {
            return Err("No streams found");
        }
        Ok(self.dir_entries.keys().cloned().collect())
    }

    /// Returns an iterator over all parsed directory entries and their names.
    pub fn streams(&self) -> impl Iterator<Item = (&str, &DirectoryEntry)> {
        self.dir_entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Retrieves the size in bytes of the specified stream by name.
    ///
    /// Returns an error if the stream does not exist in the directory.
    pub fn get_stream_size(
        &self,
        stream_name: &str,
    ) -> Result<u64, &'static str> {
        self.dir_entries
            .get(stream_name)
            .map(|e| e.size)
            .ok_or("Stream not found")
    }

    /// Retrieves the contents of the specified stream by name.
    ///
    /// Streams smaller than 4,096 bytes (excluding the Root Storage stream) are
    /// read from the Mini Stream via MiniFAT. Larger streams and the Root
    /// Storage stream are read from regular sectors via the FAT. If the stream
    /// data is contiguous in the underlying file, a zero-copy borrowed slice
    /// is returned.
    pub fn get_stream_data(
        &self,
        stream_name: &str,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        let entry =
            self.dir_entries.get(stream_name).ok_or("Stream not found")?;

        if entry.size < 4096 && entry.stream_type != DirEntryType::RootStorage
        {
            self.get_mini_stream_data(entry.start_sector, entry.size)
        } else {
            self.get_regular_stream_data(entry.start_sector, entry.size)
        }
    }

    /// Converts a 0-indexed regular sector number into an absolute byte offset
    /// within the file data.
    ///
    /// Regular sectors begin after the MS-CFB header sector (`self.sector_size`).
    fn sector_to_offset(&self, sector: u32) -> u64 {
        // The first regular sector begins at byte offset `self.sector_size` (512 in v3,
        // 4096 in v4). The theoretical maximum offset for an OLE file is ~2 TB,
        // so the result must be u64 — it does not fit in a 32-bit usize on 32-bit targets.
        self.sector_size as u64 + sector as u64 * self.sector_size as u64
    }

    /// Reads a single regular sector from the file data as a slice of length
    /// `self.sector_size`.
    ///
    /// Returns an error if the sector offset or size extends beyond the file
    /// data.
    fn read_sector(&self, sector: u32) -> Result<&'a [u8], &'static str> {
        let offset = self.sector_to_offset(sector);
        // Narrow to usize for slice indexing; any offset that doesn't fit in
        // usize is necessarily beyond the in-memory data slice.
        let offset = usize::try_from(offset)
            .map_err(|_| "Sector offset exceeds address space")?;
        if offset + self.sector_size > self.data.len() {
            return Err("Sector read out of bounds");
        }
        Ok(&self.data[offset..offset + self.sector_size])
    }

    /// Retrieves the next sector number in the File Allocation Table (FAT)
    /// chain for the given regular sector.
    fn get_fat_entry(&self, sector: u32) -> Result<u32, &'static str> {
        let entry_index = sector as usize;
        let entries_per_sector = self.sector_size / 4;
        let fat_sector_index = entry_index / entries_per_sector;
        if fat_sector_index >= self.fat_sectors.len() {
            return Err("FAT entry sector index out of range");
        }
        let fat_sector = self.fat_sectors[fat_sector_index];
        let fat = self.read_sector(fat_sector)?;
        let fat_entry_offset = (entry_index % entries_per_sector) * 4;
        parse_u32_at(fat, fat_entry_offset)
    }

    /// Traverses a regular FAT sector chain starting from `start_sector`,
    /// collecting all sector numbers until `ENDOFCHAIN`, `FREESECT`, or a
    /// cycle is encountered.
    fn follow_chain(&self, start_sector: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        if start_sector >= MAX_REGULAR_SECTOR {
            return chain;
        }

        let mut current = start_sector;
        while current < MAX_REGULAR_SECTOR {
            // Prevent cycles by keeping track of visited sectors
            if chain.contains(&current) {
                // We've seen this sector before - it's a cycle
                break;
            }

            chain.push(current);

            let next = match self.get_fat_entry(current) {
                Ok(n) => n,
                Err(_) => break,
            };

            // Check validity of next sector
            if next >= MAX_REGULAR_SECTOR
                || next == FREESECT
                || next == ENDOFCHAIN
            {
                break;
            }

            current = next;
        }
        chain
    }

    /// Parses a 128-byte MS-CFB Directory Entry from the given byte offset,
    /// decoding its UTF-16LE name and stripping any leading system control
    /// characters.
    fn read_directory_entry(
        &self,
        offset: usize,
    ) -> Result<DirectoryEntry, &'static str> {
        if offset + 128 > self.data.len() {
            return Err("Incomplete directory entry");
        }

        let name_len = parse_u16_at(self.data, offset + 64)? as usize;
        if !(2..=64).contains(&name_len) {
            return Err("Invalid name length");
        }

        let name_bytes = &self.data[offset..offset + name_len];

        // The name length stored is in bytes (including the null terminator).
        // Since it is UTF-16 LE, each character takes 2 bytes.
        // The length of units should exclude the trailing null character (2 bytes).
        let name_units_len = (name_len / 2).saturating_sub(1);
        let mut utf16_units = Vec::with_capacity(name_units_len);
        for i in 0..name_units_len {
            let unit = parse_u16_at(name_bytes, i * 2)?;
            utf16_units.push(unit);
        }

        let mut name = String::from_utf16(&utf16_units)
            .map_err(|_| "Invalid UTF-16 stream name")?;

        // According to Microsoft OLE Compound File Binary Format specifications,
        // standard system streams are prefixed with leading control bytes:
        // - U+0005 (e.g., \u{0005}SummaryInformation, \u{0005}DocumentSummaryInformation)
        //   defined in [MS-OLEPS] Section 2.21.
        // - U+0001 (e.g., \u{0001}CompObj, \u{0001}Ole)
        //   defined in standard OLE Compound Document specs for system streams.
        //
        // We strip these leading control characters (values < '\u{20}') to
        // prevent control characters from breaking standard JSON/YAML
        // serializers.
        if name.starts_with(|c: char| c < '\u{20}') {
            name.remove(0);
        }

        let stream_type = DirEntryType::from(self.data[offset + 66]);
        let start_sector = parse_u32_at(self.data, offset + 116)?;
        let size_32 = parse_u32_at(self.data, offset + 120)?;
        let size = size_32 as u64;

        Ok(DirectoryEntry { name, size, start_sector, stream_type })
    }

    /// Core helper that extracts stream data by following a FAT or MiniFAT
    /// chain.
    ///
    /// Attempts zero-copy slicing from `stream_data` if it is a borrowed slice
    /// and if the sector chain is strictly sequential. Falls back to allocating
    /// a vector and reading sectors from `stream_data`.
    fn get_stream_data_by_chain(
        &self,
        stream_data: &Cow<'a, [u8]>,
        base_offset: u64,
        sector_size: usize,
        start_sector: u32,
        size: usize,
        next_sector_fn: impl Fn(u32) -> Result<u32, &'static str>,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }

        // Fast path: zero-copy slicing if stream_data is borrowed.
        if let Cow::Borrowed(src) = stream_data
            && let Ok(slice) = self.try_get_stream_slice(
                src,
                base_offset,
                sector_size,
                start_sector,
                size,
                &next_sector_fn,
            )
        {
            return Ok(Cow::Borrowed(slice));
        }

        // Fallback: Sector-by-sector gathering.
        let fallback_slice = stream_data.as_ref();
        let mut data = Vec::with_capacity(size);
        let mut current_sector = start_sector;
        let mut visited = Vec::new();

        while current_sector < MAX_REGULAR_SECTOR && data.len() < size {
            if visited.contains(&current_sector) {
                return Err("Circular reference detected in sector chain");
            }
            visited.push(current_sector);

            let sector_offset = base_offset
                .saturating_add(current_sector as u64 * sector_size as u64);
            let offset = usize::try_from(sector_offset)
                .map_err(|_| "Sector offset exceeds address space")?;

            if offset >= fallback_slice.len() {
                return Err("Sector read out of bounds");
            }

            let bytes_to_read = std::cmp::min(sector_size, size - data.len());
            if offset + bytes_to_read > fallback_slice.len() {
                return Err("Sector read extends beyond available data");
            }

            data.extend_from_slice(
                &fallback_slice[offset..offset + bytes_to_read],
            );

            if data.len() < size {
                let next = next_sector_fn(current_sector)?;
                if next == ENDOFCHAIN || next >= MAX_REGULAR_SECTOR {
                    break;
                }
                current_sector = next;
            }
        }

        if data.len() != size {
            return Err("Incomplete stream data");
        }

        Ok(Cow::Owned(data))
    }

    /// Verifies whether a sector chain for `size` bytes starting from `start_sector`
    /// is strictly sequential and within bounds of `src`.
    ///
    /// If so, returns a zero-copy slice of `src`. Returns an error if the chain is
    /// fragmented or out of bounds.
    fn try_get_stream_slice(
        &self,
        src: &'a [u8],
        base_offset: u64,
        sector_size: usize,
        start_sector: u32,
        size: usize,
        next_sector_fn: &impl Fn(u32) -> Result<u32, &'static str>,
    ) -> Result<&'a [u8], &'static str> {
        if start_sector >= MAX_REGULAR_SECTOR {
            return Err("Invalid start sector");
        }

        let needed_sectors = size.div_ceil(sector_size);
        let mut current_sector = start_sector;

        for _ in 1..needed_sectors {
            let next = next_sector_fn(current_sector)?;
            if next != current_sector + 1
                || next == ENDOFCHAIN
                || next >= MAX_REGULAR_SECTOR
            {
                return Err("Stream is fragmented");
            }
            current_sector = next;
        }

        let start_offset = base_offset
            .saturating_add(start_sector as u64 * sector_size as u64);
        let start_offset = usize::try_from(start_offset)
            .map_err(|_| "Sector offset exceeds address space")?;
        let total_span_size = needed_sectors * sector_size;

        if start_offset + total_span_size > src.len() {
            return Err("Stream sectors out of bounds");
        }

        Ok(&src[start_offset..start_offset + size])
    }

    /// Retrieves the contents of a regular stream starting at `start_sector`
    /// with length `size`.
    ///
    /// Attempts to return a zero-copy borrowed slice if the sector chain is
    /// strictly sequential and unfragmented. Otherwise, allocates a vector and
    /// gathers sectors.
    fn get_regular_stream_data(
        &self,
        start_sector: u32,
        size: u64,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        if size > MAX_STREAM_SIZE {
            return Err("Stream size exceeds maximum allowed size");
        }
        self.get_stream_data_by_chain(
            &Cow::Borrowed(self.data),
            self.sector_size as u64,
            self.sector_size,
            start_sector,
            size as usize,
            |sec| self.get_fat_entry(sec),
        )
    }

    /// Retrieves the contents of the Root Storage stream (also known as the
    /// Mini Stream), which contains the data sectors for all mini streams.
    fn get_root_mini_stream_data(
        &self,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        self.get_regular_stream_data(
            self.mini_stream_start,
            self.mini_stream_size,
        )
    }

    /// Retrieves the next mini sector number in the MiniFAT chain for the given
    /// mini sector.
    fn get_minifat_entry(
        &self,
        mini_sector: u32,
    ) -> Result<u32, &'static str> {
        if self.mini_fat_sectors.is_empty() {
            return Ok(ENDOFCHAIN);
        }

        let entry_index = mini_sector as usize;
        let entries_per_sector = self.sector_size / 4;
        let fat_sector_index = entry_index / entries_per_sector;
        if fat_sector_index >= self.mini_fat_sectors.len() {
            return Ok(ENDOFCHAIN);
        }
        let sector = self.mini_fat_sectors[fat_sector_index];
        let fat = self.read_sector(sector)?;
        let offset = (entry_index % entries_per_sector) * 4;
        parse_u32_at(fat, offset)
    }

    /// Retrieves the contents of a mini stream starting at `start_mini_sector`
    /// with length `size`.
    ///
    /// Attempts zero-copy slicing if both the Root Storage stream and MiniFAT
    /// sector chain are contiguous. Otherwise, allocates a vector and gathers
    /// mini sectors.
    fn get_mini_stream_data(
        &self,
        start_mini_sector: u32,
        size: u64,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        if size > MAX_STREAM_SIZE {
            return Err("Stream size exceeds maximum allowed size");
        }

        if self.mini_stream_size == 0 {
            return Err("No mini stream present");
        }

        let mini_stream_data = self.get_root_mini_stream_data()?;

        self.get_stream_data_by_chain(
            &mini_stream_data,
            0,
            self.mini_sector_size,
            start_mini_sector,
            size as usize,
            |sec| self.get_minifat_entry(sec),
        )
    }
}

/// Helper function to parse a little-endian `u16` from a byte slice at the
/// given offset.
fn parse_u16_at(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    if offset + 2 > data.len() {
        return Err("Buffer too small for u16");
    }
    let slice = &data[offset..offset + 2];
    match le_u16::<&[u8], NomError<&[u8]>>(slice) {
        Ok((_, val)) => Ok(val),
        Err(_) => Err("Failed to parse u16"),
    }
}

/// Helper function to parse a little-endian `u32` from a byte slice at the
/// given offset.
fn parse_u32_at(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    if offset + 4 > data.len() {
        return Err("Buffer too small for u32");
    }
    let slice = &data[offset..offset + 4];
    match le_u32::<&[u8], NomError<&[u8]>>(slice) {
        Ok((_, val)) => Ok(val),
        Err(_) => Err("Failed to parse u32"),
    }
}
