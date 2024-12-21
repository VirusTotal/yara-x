use std::collections::HashMap;

const OLECF_SIGNATURE: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const SECTOR_SHIFT: u16 = 9;
const MINI_SECTOR_SHIFT: u16 = 6;
const DIRECTORY_ENTRY_SIZE: u64 = 128;

// Directory Entry Types
const STORAGE_TYPE: u8 = 1;
const STREAM_TYPE: u8 = 2;
const ROOT_STORAGE_TYPE: u8 = 5;

// Special sectors
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FREESECT: u32 = 0xFFFFFFFF;
const MAX_REGULAR_SECTOR: u32 = 0xFFFFFFFA;

pub struct OLECFParser<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    fat_sectors: Vec<u32>,
    directory_sectors: Vec<u32>,
    mini_fat_sectors: Vec<u32>,
    dir_entries: HashMap<String, DirectoryEntry>,
    mini_stream_start: u32,
    mini_stream_size: u64,
}

struct DirectoryEntry {
    name: String,
    size: u64,
    start_sector: u32,
    stream_type: u8,
}

impl<'a> OLECFParser<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut parser = OLECFParser {
            data,
            sector_size: 1 << SECTOR_SHIFT,
            mini_sector_size: 1 << MINI_SECTOR_SHIFT,
            fat_sectors: Vec::new(),
            directory_sectors: Vec::new(),
            mini_fat_sectors: Vec::new(),
            dir_entries: HashMap::new(),
            mini_stream_start: 0,
            mini_stream_size: 0,
        };

        parser.parse_header()?;
        parser.parse_directory()?;

        if parser.mini_stream_size > 0 && parser.mini_stream_start >= MAX_REGULAR_SECTOR {
            return Err("Invalid mini stream start sector");
        }

        Ok(parser)
    }

    fn read_u16(data: &[u8], offset: usize) -> Result<u16, &'static str> {
        if offset + 2 > data.len() {
            return Err("Buffer too small for u16");
        }
        Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
    }

    fn read_u32(data: &[u8], offset: usize) -> Result<u32, &'static str> {
        if offset + 4 > data.len() {
            return Err("Buffer too small for u32");
        }
        Ok(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    }

    pub fn is_valid_header(&self) -> bool {
        self.data.len() >= OLECF_SIGNATURE.len() && &self.data[..OLECF_SIGNATURE.len()] == OLECF_SIGNATURE
    }

    fn parse_header(&mut self) -> Result<(), &'static str> {
        if !self.is_valid_header() {
            return Err("Invalid OLECF signature");
        }

        let byte_order = Self::read_u16(self.data, 28)?;
        if byte_order != 0xFFFE {
            return Err("Invalid byte order mark");
        }

        let num_fat_sectors = Self::read_u32(self.data, 44)?;
        let first_dir_sector = Self::read_u32(self.data, 48)?;
        let first_mini_fat = Self::read_u32(self.data, 60)?;
        let mini_fat_count = Self::read_u32(self.data, 64)?;
        let first_difat_sector = Self::read_u32(self.data, 68)?;
        let difat_count = Self::read_u32(self.data, 72)?;

        // DIFAT entries in header
        let mut difat_entries = Vec::new();
        let mut offset = 76;
        for _ in 0..109 {
            if offset + 4 > self.data.len() {
                break;
            }
            let sector = Self::read_u32(self.data, offset)?;
            if sector < MAX_REGULAR_SECTOR {
                difat_entries.push(sector);
            }
            offset += 4;
        }

        // Follow DIFAT chain
        let mut current_difat = first_difat_sector;
        for _ in 0..difat_count {
            if current_difat >= MAX_REGULAR_SECTOR {
                break;
            }
            let difat_data = self.read_sector(current_difat)?;
            let entries_per_difat = (self.sector_size / 4) - 1;
            for i in 0..entries_per_difat {
                let s = Self::read_u32(difat_data, i * 4)?;
                if s < MAX_REGULAR_SECTOR {
                    difat_entries.push(s);
                }
            }
            current_difat = Self::read_u32(difat_data, self.sector_size - 4)?;
        }

        if difat_entries.is_empty() && num_fat_sectors > 0 {
            return Err("No FAT sectors found despite nonzero FAT count");
        }
        self.fat_sectors = difat_entries;

        // Directory chain
        if first_dir_sector < MAX_REGULAR_SECTOR {
            self.directory_sectors = self.follow_chain(first_dir_sector);
        } else {
            return Err("No valid directory start sector");
        }

        // MiniFAT chain
        if mini_fat_count > 0 && first_mini_fat < MAX_REGULAR_SECTOR {
            self.mini_fat_sectors = self.follow_chain(first_mini_fat);
        }

        Ok(())
    }

    fn sector_to_offset(&self, sector: u32) -> usize {
        512 + (sector as usize * self.sector_size)
    }

    fn read_sector(&self, sector: u32) -> Result<&[u8], &'static str> {
        let offset = self.sector_to_offset(sector);
        if offset + self.sector_size > self.data.len() {
            return Err("Sector read out of bounds");
        }
        Ok(&self.data[offset..offset + self.sector_size])
    }

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
        Self::read_u32(fat, fat_entry_offset)
    }

    fn follow_chain(&self, start_sector: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        if start_sector >= MAX_REGULAR_SECTOR {
            return chain;
        }

        let mut current = start_sector;
        while current < MAX_REGULAR_SECTOR {
            chain.push(current);
            let next = match self.get_fat_entry(current) {
                Ok(n) => n,
                Err(_) => break,
            };
            if next >= MAX_REGULAR_SECTOR || next == FREESECT || next == ENDOFCHAIN {
                break;
            }
            current = next;
        }
        chain
    }

    fn read_directory_entry(&self, offset: usize) -> Result<DirectoryEntry, &'static str> {
        if offset + 128 > self.data.len() {
            return Err("Incomplete directory entry");
        }

        let name_len = Self::read_u16(self.data, offset + 64)? as usize;
        if name_len < 2 || name_len > 64 {
            return Err("Invalid name length");
        }

        let name_bytes = &self.data[offset..offset + name_len];
        let filtered: Vec<u8> = name_bytes.iter().copied().filter(|&b| b != 0).collect();
        let name = String::from_utf8_lossy(&filtered).to_string();

        let stream_type = self.data[offset + 66];
        let start_sector = Self::read_u32(self.data, offset + 116)?;   // start sector
        let size_32 = Self::read_u32(self.data, offset + 120)?;        // size is 4 bytes, read as u32
        let size = size_32 as u64;

        Ok(DirectoryEntry {
            name,
            size,
            start_sector,
            stream_type,
        })
    }

    fn parse_directory(&mut self) -> Result<(), &'static str> {
        if self.directory_sectors.is_empty() {
            return Err("No directory sectors found");
        }

        for &sector in &self.directory_sectors {
            let mut entry_offset = 0;

            while entry_offset + DIRECTORY_ENTRY_SIZE as usize <= self.sector_size {
                let abs_offset = self.sector_to_offset(sector) + entry_offset;
                if abs_offset + DIRECTORY_ENTRY_SIZE as usize > self.data.len() {
                    break;
                }
                match self.read_directory_entry(abs_offset) {
                    Ok(entry) => {
                        if entry.stream_type == ROOT_STORAGE_TYPE {
                            self.mini_stream_start = entry.start_sector;
                            self.mini_stream_size = entry.size;
                        }
                        if entry.stream_type == STORAGE_TYPE
                            || entry.stream_type == STREAM_TYPE
                            || entry.stream_type == ROOT_STORAGE_TYPE
                        {
                            self.dir_entries.insert(entry.name.clone(), entry);
                        }
                    }
                    Err(_) => {}
                }
                entry_offset += DIRECTORY_ENTRY_SIZE as usize;
            }
        }

        Ok(())
    }

    pub fn get_stream_names(&self) -> Result<Vec<String>, &'static str> {
        if self.dir_entries.is_empty() {
            return Err("No streams found");
        }
        Ok(self.dir_entries.keys().cloned().collect())
    }

    pub fn get_stream_size(&self, stream_name: &str) -> Result<u64, &'static str> {
        self.dir_entries.get(stream_name).map(|e| e.size).ok_or("Stream not found")
    }

    pub fn get_stream_data(&self, stream_name: &str) -> Result<Vec<u8>, &'static str> {
        let entry = self.dir_entries.get(stream_name)
            .ok_or("Stream not found")?;

        if entry.size < 4096 && entry.stream_type != ROOT_STORAGE_TYPE {
            self.get_mini_stream_data(entry.start_sector, entry.size)
        } else {
            self.get_regular_stream_data(entry.start_sector, entry.size)
        }
    }

    fn get_regular_stream_data(&self, start_sector: u32, size: u64) -> Result<Vec<u8>, &'static str> {
        let mut data = Vec::with_capacity(size as usize);
        let mut current_sector = start_sector;
        let mut total_read = 0;

        while current_sector < MAX_REGULAR_SECTOR && total_read < size as usize {
            let sector_data = self.read_sector(current_sector)?;
            let bytes_to_read = std::cmp::min(self.sector_size, size as usize - total_read);

            data.extend_from_slice(&sector_data[..bytes_to_read]);
            total_read += bytes_to_read;

            if total_read < size as usize {
                let next = self.get_fat_entry(current_sector)?;
                if next == ENDOFCHAIN || next >= MAX_REGULAR_SECTOR {
                    break;
                }
                current_sector = next;
            }
        }

        if data.len() != size as usize {
            return Err("Incomplete stream data");
        }

        Ok(data)
    }

    fn get_root_mini_stream_data(&self) -> Result<Vec<u8>, &'static str> {
        // The mini stream is stored as a regular FAT-based stream
        self.get_regular_stream_data(self.mini_stream_start, self.mini_stream_size)
    }

    fn get_minifat_entry(&self, mini_sector: u32) -> Result<u32, &'static str> {
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
        Self::read_u32(fat, offset)
    }

    fn get_mini_stream_data(&self, start_mini_sector: u32, size: u64) -> Result<Vec<u8>, &'static str> {
        if self.mini_stream_size == 0 {
            return Err("No mini stream present");
        }

        let mini_stream_data = self.get_root_mini_stream_data()?;
        let mini_data_len = mini_stream_data.len();

        let mut data = Vec::with_capacity(size as usize);
        let mut current = start_mini_sector;

        while current < MAX_REGULAR_SECTOR && data.len() < size as usize {
            let mini_offset = current as usize * self.mini_sector_size;
            if mini_offset >= mini_data_len {
                return Err("Mini stream offset out of range");
            }

            let bytes_to_read = std::cmp::min(self.mini_sector_size, size as usize - data.len());
            if mini_offset + bytes_to_read > mini_data_len {
                return Err("Mini stream extends beyond available data");
            }

            data.extend_from_slice(&mini_stream_data[mini_offset..mini_offset + bytes_to_read]);

            if data.len() < size as usize {
                let next = self.get_minifat_entry(current)?;
                if next == ENDOFCHAIN || next >= MAX_REGULAR_SECTOR {
                    break;
                }
                current = next;
            }
        }

        if data.len() != size as usize {
            return Err("Incomplete mini stream data");
        }

        Ok(data)
    }
}
