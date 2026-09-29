use std::cmp::min;
use std::mem;
use std::num::NonZeroUsize;

use nom::bytes::complete::{take, take_while};
use nom::combinator::{cond, map_res, verify};
use nom::multi::{fold_many0, many_till};
use nom::number::complete::{le_u16, le_u32, le_u64, le_u128};
use nom::{Err, Input, ToUsize};
use nom::{IResult, Needed, Parser};
use protobuf::EnumOrUnknown;
use uuid::Uuid;

type NomError<'a> = nom::error::Error<&'a [u8]>;

use crate::modules::protos::lnk::{
    DriveType, Lnk, ShellItem, ShellItemType, ShowCommand, TrackerData,
};

/// A Windows LNK file parser.
pub struct LnkParser {
    result: Lnk,
}

impl LnkParser {
    /// Creates a new parser for Windows LNK files.
    pub fn new() -> Self {
        Self { result: Lnk::default() }
    }

    /// Parses a LNK file and produces a [`Lnk`] protobuf containing metadata
    /// extracted from the file.
    pub fn parse<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<Lnk, Err<nom::error::Error<&'a [u8]>>> {
        // The structure of a LNK files looks like this:
        //
        // SHELL_LINK = SHELL_LINK_HEADER
        //              [LINKTARGET_IDLIST]
        //              [LINKINFO]
        //              [STRING_DATA]
        //              *EXTRA_DATA
        //
        let total_size = input.len();
        // Parse the header.
        let (
            input,
            (
                _header_size,
                _clsid,
                link_flags,
                file_attributes,
                creation_time,
                access_time,
                write_time,
                file_size,
                icon_index,
                show_command,
                _hotkey,
                _, // reserved
                _, // reserved
                _, // reserved
            ),
        ) = (
            // The first 4 bytes is the size of the header, which should be
            // 0x4c.
            verify(le_u32, |&header_size| header_size == 0x4c),
            // After the size comes the CLSID which must be:
            // 00021401-0000-0000-C000-000000000046
            verify(le_u128, |&clsid| {
                clsid == 0x4600_0000_0000_00C0_0000_0000_0002_1401
            }),
            le_u32, // link_flags,
            le_u32, // file_attributes
            le_u64, // creation_time
            le_u64, // access_time
            le_u64, // write_time
            le_u32, // file_size
            le_u32, // icon_index
            le_u32, // show_command
            le_u16, // _hotkey
            le_u16, // reserved
            le_u32, // reserved
            le_u32, // reserved
        )
            .parse(input)?;

        self.result.is_lnk = Some(true);
        self.result.file_attributes = Some(file_attributes);
        self.result.creation_time = filetime_to_unix_timestamp(creation_time);
        self.result.access_time = filetime_to_unix_timestamp(access_time);
        self.result.write_time = filetime_to_unix_timestamp(write_time);
        self.result.file_size = Some(file_size);
        self.result.icon_index = Some(icon_index);
        self.result.show_command = show_command
            .try_into()
            .ok()
            .map(EnumOrUnknown::<ShowCommand>::from_i32);

        let unicode = link_flags & Self::IS_UNICODE != 0;

        // Parse the sections that come after the header. Malformed or
        // malicious files (e.g. CVE-2010-2568 exploits) may declare structure
        // sizes that exceed the actual file, causing this to fail. In that
        // case the header metadata that was already extracted is still
        // returned, instead of discarding everything and reporting the file
        // as not being a LNK file.
        let _ = self.parse_body(input, link_flags, unicode, total_size);

        Ok(mem::take(&mut self.result))
    }

    /// Parses the sections that follow the header: the link target ID list,
    /// the link info, the string data, and the extra data. Any of these can
    /// fail on malformed files, in which case the error is returned and the
    /// caller keeps whatever was parsed so far.
    fn parse_body<'a>(
        &mut self,
        mut input: &'a [u8],
        link_flags: u32,
        unicode: bool,
        total_size: usize,
    ) -> IResult<&'a [u8], ()> {
        // Parse the link target list (LINKTARGET_IDLIST), if present.
        //
        // IDLIST = *ITEMID TERMINALID
        (input, _) = cond(
            link_flags & Self::HAS_LINK_TARGET_ID_LIST != 0,
            self.parse_link_target_id_list(),
        )
        .parse(input)?;

        // Parse the link info (LINKINFO), if present.
        (input, _) = cond(
            link_flags & Self::HAS_LINK_INFO != 0,
            self.parse_link_info(),
        )
        .parse(input)?;

        // Parse the string data (STRING_DATA).
        //
        // STRING_DATA = [NAME_STRING] [RELATIVE_PATH] [WORKING_DIR]
        //               [COMMAND_LINE_ARGUMENTS] [ICON_LOCATION]
        (input, self.result.name) = cond(
            link_flags & Self::HAS_NAME != 0,
            Self::parse_string_data(unicode, Some(260)),
        )
        .parse(input)?;

        (input, self.result.relative_path) = cond(
            link_flags & Self::HAS_RELATIVE_PATH != 0,
            Self::parse_string_data(unicode, Some(260)),
        )
        .parse(input)?;

        (input, self.result.working_dir) = cond(
            link_flags & Self::HAS_WORKING_DIR != 0,
            Self::parse_string_data(unicode, Some(260)),
        )
        .parse(input)?;

        (input, self.result.cmd_line_args) = cond(
            link_flags & Self::HAS_ARGUMENTS != 0,
            Self::parse_string_data(unicode, None),
        )
        .parse(input)?;

        (input, self.result.icon_location) = cond(
            link_flags & Self::HAS_ICON_LOCATION != 0,
            Self::parse_string_data(unicode, Some(260)),
        )
        .parse(input)?;

        // Parse the extra data.
        //
        // EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK
        let overlay = many_till(
            self.parse_extra_data_block(),
            // The terminal block has size < 4.
            verify(le_u32, |block_size| *block_size < 4),
        )
        .parse(input)
        .map(|(overlay, _)| overlay);

        if let Ok(overlay) = overlay {
            // Any remaining data is outside the specification and its considered
            // an overlay. The field `overlay_offset` is initialized only if there
            // is some overlay.
            if !overlay.is_empty() {
                self.result.overlay_offset =
                    Some((total_size - overlay.len()).try_into().unwrap());
            }

            self.result.overlay_size = overlay.len().try_into().ok();
        }

        Ok((input, ()))
    }
}

impl LnkParser {
    const HAS_LINK_TARGET_ID_LIST: u32 = 0x00000001;
    const HAS_LINK_INFO: u32 = 0x00000002;
    const HAS_NAME: u32 = 0x00000004;
    const HAS_RELATIVE_PATH: u32 = 0x00000008;
    const HAS_WORKING_DIR: u32 = 0x00000010;
    const HAS_ARGUMENTS: u32 = 0x00000020;
    const HAS_ICON_LOCATION: u32 = 0x00000040;
    const IS_UNICODE: u32 = 0x00000080;

    const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x00000001;
    const COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX: u32 = 0x00000002;

    fn parse_link_target_id_list(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            // The list starts with a 2-byte size for the whole IDList (the
            // sequence of ItemIDs plus the terminal ID). The size does not
            // include the size field itself.
            let (after_size, list_size) = le_u16(input)?;

            // Clamp the declared size to what is actually available. Some
            // malformed or malicious files (e.g. CVE-2010-2568 exploits)
            // declare a size larger than the file. Being lenient here allows
            // the shell items to still be parsed.
            let list_size = min(list_size as usize, after_size.len());
            let (remainder, mut list) = take(list_size)(after_size)?;

            // Iterate over the ItemIDs until the terminal ID (an item with
            // size 0) or the end of the list is found.
            while list.len() >= 2 {
                let (rest, item_size) = le_u16(list)?;
                // An item ID with size 0 is the terminal one.
                if item_size == 0 {
                    break;
                }
                // The size includes the 2-byte size field itself. Clamp the
                // item's data to what is available.
                let data_len =
                    min((item_size as usize).saturating_sub(2), rest.len());
                let (after_item, item_data) = take(data_len)(rest)?;
                self.parse_shell_item(item_data);
                list = after_item;
            }

            Ok((remainder, ()))
        }
    }

    /// Maps a shell item class type indicator to a [`ShellItemType`]
    /// category. The mapping follows the type-indicator table in the
    /// reverse-engineered shell item format documentation and the LnkParse3
    /// implementation: the volume (0x20-0x2F), file entry (0x30-0x3F) and
    /// network location (0x40-0x4F) items are identified by masking the class
    /// type indicator with 0x70, while the remaining categories are matched
    /// exactly. Returns `None` when the class type indicator is not
    /// recognized.
    fn classify_shell_item(class: u8) -> Option<ShellItemType> {
        match class & 0x70 {
            0x20 => Some(ShellItemType::VOLUME),
            0x30 => Some(ShellItemType::FILE_ENTRY),
            0x40 => Some(ShellItemType::NETWORK_LOCATION),
            _ => match class {
                0x00 => Some(ShellItemType::CONTROL_PANEL_CPL),
                0x01 => Some(ShellItemType::CONTROL_PANEL_CATEGORY),
                0x1E | 0x1F => Some(ShellItemType::ROOT_FOLDER),
                0x52 => Some(ShellItemType::COMPRESSED_FOLDER),
                0x61 => Some(ShellItemType::URI),
                0x70 | 0x71 => Some(ShellItemType::CONTROL_PANEL),
                0x72 => Some(ShellItemType::PRINTERS),
                0x73 => Some(ShellItemType::COMMON_PLACES_FOLDER),
                0x74 => Some(ShellItemType::USERS_FILES_FOLDER),
                _ => None,
            },
        }
    }

    /// Parses a single shell item (the `Data` field of an `ItemID`, without
    /// the leading `ItemIDSize` field) and appends the extracted information
    /// to the result.
    ///
    /// The `LinkTargetIDList` and `ItemID` container structures are defined in
    /// the Microsoft [MS-SHLLINK] specification (sections 2.2 and 2.2.2).
    /// However, MS-SHLLINK explicitly leaves the internal layout of each
    /// `ItemID`'s `Data` field undefined: it states that the data "is defined
    /// by the source that corresponds to the location in the target namespace"
    /// (i.e. by the shell folder / namespace extension that produced it), and
    /// Microsoft does not publish a specification for those structures.
    ///
    /// The class type indicator values dispatched on below (0x00 control panel
    /// CPL file, 0x1E/0x1F root folder, 0x20-0x2F volume, 0x30-0x3F file entry,
    /// 0x40-0x4F network location), the `& 0x70` masking, and the per-type
    /// field offsets therefore come from the community's reverse-engineered
    /// documentation of the shell item format, primarily [libfwsi] by Joachim
    /// Metz. They are decoded on a best-effort basis.
    ///
    /// [MS-SHLLINK]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
    /// [libfwsi]: https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc
    fn parse_shell_item(&mut self, data: &[u8]) {
        let class = match data.first() {
            Some(class) => *class,
            None => return,
        };

        let mut item = ShellItem::new();
        item.data = Some(data.get(1..).unwrap_or_default().to_vec());

        item.item_type = Some(
            Self::classify_shell_item(class)
                .map(EnumOrUnknown::new)
                .unwrap_or_else(|| EnumOrUnknown::from_i32(class as i32)),
        );

        match class {
            // Control panel CPL file shell item. Contains the path to the CPL
            // file, which is the payload abused by CVE-2010-2568.
            0x00 => {
                item.cpl_file_path = Self::parse_cpl_file_path(data);
            }
            // Root folder shell item, carries a shell folder GUID.
            0x1E | 0x1F => {
                item.root_folder_id = Self::parse_shell_guid(data);
            }
            _ => match class & 0x70 {
                // Volume shell item. When the "has name" flag (0x01) is set it
                // carries a volume name, otherwise a volume identifier (GUID).
                0x20 => {
                    if class & 0x01 != 0 {
                        item.volume_name = data
                            .get(1..21)
                            .map(|s| Self::parse_shell_string(s, false));
                    } else {
                        item.volume_id = Self::parse_shell_guid(data);
                    }
                }
                // File entry shell item, carries the file or directory name.
                0x30 => {
                    let unicode = class & 0x04 != 0;
                    item.file_entry_name = data
                        .get(12..)
                        .map(|s| Self::parse_shell_string(s, unicode));
                }
                // Network location shell item, carries a UNC path.
                0x40 => {
                    item.network_location = data
                        .get(3..)
                        .map(|s| Self::parse_shell_string(s, false));
                }
                _ => {}
            },
        }

        self.result.target_id_list.push(item);
    }

    /// Parses the CPL file path of a control panel CPL file shell item.
    fn parse_cpl_file_path(data: &[u8]) -> Option<String> {
        // The strings can be stored either in ASCII or UTF-16. They are told
        // apart by inspecting byte 10: in the UTF-16 layout the strings start
        // at offset 22 and byte 10 is the null high byte of a character, while
        // in the ASCII layout the string starts at offset 10.
        let unicode = *data.get(10)? == 0x00;
        if unicode {
            data.get(22..).map(|s| Self::parse_shell_string(s, true))
        } else {
            data.get(10..).map(|s| Self::parse_shell_string(s, false))
        }
    }

    /// Parses a shell folder GUID located right after the class type
    /// indicator and its sort index / flags byte (offset 2, 16 bytes).
    fn parse_shell_guid(data: &[u8]) -> Option<String> {
        data.get(2..18)
            .and_then(|s| Uuid::from_slice_le(s).ok())
            .map(|uuid| uuid.to_string())
    }

    /// Parses a null-terminated string in either ASCII or UTF-16 encoding.
    fn parse_shell_string(input: &[u8], unicode: bool) -> String {
        if unicode {
            Self::parse_utf16_string(input).map(|(_, s)| s).unwrap_or_default()
        } else {
            Self::parse_string(input).map(|(_, s)| s).unwrap_or_default()
        }
    }

    fn parse_link_info(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (
                optional_fields,
                (
                    size,
                    header_size,
                    flags,
                    volume_id_offset,
                    local_base_path_offset,
                    _common_network_relative_link_offset,
                    common_path_suffix_offset,
                ),
            ) = (
                le_u32, // link_info_size
                le_u32, // link_info_header_size
                le_u32, // link_info_flags,
                le_u32, // volume_id_offset
                le_u32, // local_base_path_offset
                le_u32, // common_network_relative_link_offset
                le_u32, // common_path_suffix_offset
            )
                .parse(input)?;

            let (
                _,
                (
                    local_base_path_offset_unicode,
                    common_path_suffix_offset_unicode,
                ),
            ) = (
                cond(header_size >= 0x24, le_u32),
                cond(header_size >= 0x24, le_u32),
            )
                .parse(optional_fields)?;

            let (remainder, link_info) = take(size)(input)?;

            if flags & Self::VOLUME_ID_AND_LOCAL_BASE_PATH != 0 {
                if let Some(d) = link_info.get(volume_id_offset as usize..) {
                    let _ = self.parse_volume_id()(d);
                }
                match local_base_path_offset_unicode {
                    Some(offset) if offset > 0 => {
                        if let Some(string) = link_info.get(offset as usize..)
                        {
                            self.result.local_base_path =
                                Self::parse_utf16_string(string)
                                    .map(|(_, path)| Some(path))
                                    .unwrap_or(None);
                        }
                    }
                    _ => {
                        if let Some(string) =
                            link_info.get(local_base_path_offset as usize..)
                        {
                            self.result.local_base_path =
                                Self::parse_string(string)
                                    .map(|(_, path)| Some(path))
                                    .unwrap_or(None);
                        }
                    }
                }
            }

            if flags & Self::COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX != 0
            {
                match common_path_suffix_offset_unicode {
                    Some(offset) if offset > 0 => {
                        if let Some(string) = link_info.get(offset as usize..)
                        {
                            self.result.common_path_suffix =
                                Self::parse_utf16_string(string)
                                    .map(|(_, path)| Some(path))
                                    .unwrap_or(None);
                        }
                    }
                    _ => {
                        if let Some(string) =
                            link_info.get(common_path_suffix_offset as usize..)
                        {
                            self.result.common_path_suffix =
                                Self::parse_string(string)
                                    .map(|(_, path)| Some(path))
                                    .unwrap_or(None);
                        }
                    }
                }
            }

            Ok((remainder, ()))
        }
    }

    fn parse_volume_id(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (
                optional,
                (
                    volume_id_size,
                    drive_type,
                    drive_serial_number,
                    mut volume_label_offset,
                ),
            ) = (
                le_u32, // volume_id_size
                le_u32, // drive_type
                le_u32, // drive_serial_number
                le_u32, // volume_label_offset
            )
                .parse(input)?;

            self.result.drive_type = drive_type
                .try_into()
                .ok()
                .map(EnumOrUnknown::<DriveType>::from_i32);

            self.result.drive_serial_number = Some(drive_serial_number);

            // The volume ID struct takes the first `volume_id_size` bytes of
            // `input`.
            let (remainder, volume_id) = take(volume_id_size)(input)?;

            // According to the specification if volume_label_offset is 0x14 it
            // indicates that the volume label is a unicode string. In such
            // cases the value of volume_label_offset must be ignored, and the
            // offset to the unicode string is the 4 bytes offset that comes
            // right after `volume_label_offset`.
            if volume_label_offset == 0x14 {
                (_, volume_label_offset) = le_u32(optional)?;
                if let Some(string) =
                    volume_id.get(volume_label_offset as usize..)
                {
                    // TODO: implement a protobuf type for representing strings
                    // contained within the scanned data that doesn't need
                    // copying data.
                    self.result.volume_label =
                        Self::parse_utf16_string(string)
                            .map(|(_, label)| Some(label))
                            .unwrap_or(None);
                }
            } else if let Some(string) =
                volume_id.get(volume_label_offset as usize..)
            {
                self.result.volume_label = Self::parse_string(string)
                    .map(|(_, label)| Some(label))
                    .unwrap_or(None);
            }

            Ok((remainder, ()))
        }
    }

    fn parse_extra_data_block(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (remainder, block) = Self::length_data(le_u32).parse(input)?;
            // The first 4 bytes in each block indicates its type.
            if let Ok((block_data, 0xA0000003)) =
                le_u32::<&[u8], nom::error::Error<&[u8]>>(block)
            {
                let _ = self.parse_tracker_data_block()(block_data);
            }
            Ok((remainder, ()))
        }
    }

    fn parse_tracker_data_block(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (
                remainder,
                (
                    _length,
                    version,
                    machine_id,
                    droid_volume_id,
                    droid_file_id,
                    droid_birth_volume_id,
                    droid_birth_file_id,
                ),
            ) = (
                le_u32, // length
                le_u32, // version
                // machine_id
                take(16_u8).and_then(Self::parse_string),
                // droid_volume_id
                map_res(take(16_u8), Uuid::from_slice_le),
                // droid_file_id
                map_res(take(16_u8), Uuid::from_slice_le),
                // droid_birth_volume_id
                map_res(take(16_u8), Uuid::from_slice_le),
                // droid_birth_file_id
                map_res(take(16_u8), Uuid::from_slice_le),
            )
                .parse(input)?;

            let mut tracker_data = TrackerData::new();

            tracker_data.version = Some(version);
            tracker_data.machine_id = Some(machine_id);
            tracker_data.droid_volume_id = Some(droid_volume_id.to_string());
            tracker_data.droid_file_id = Some(droid_file_id.to_string());

            tracker_data.droid_birth_volume_id =
                Some(droid_birth_volume_id.to_string());

            tracker_data.droid_birth_file_id =
                Some(droid_birth_file_id.to_string());

            self.result.tracker_data = Some(tracker_data).into();

            Ok((remainder, ()))
        }
    }

    fn parse_string_data(
        unicode: bool,
        max_len: Option<u16>,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], String> {
        move |input: &[u8]| {
            let (string, mut length) = le_u16(input)?;

            // Microsoft doesn't follow its own specification and limits the
            // length of strings to 260 characters in some cases. That's why
            // this function takes an optional argument `max_len`. If a max
            // length is specified it is used for limiting the length of the
            // string.
            // See:
            // https://github.com/VirusTotal/yara-x/issues/379
            // https://harfanglab.io/insidethelab/sadfuture-xdspy-latest-evolution/
            // https://github.com/Matmaus/LnkParse3/commit/992d064b2b5ef9cc1460e94cad7232a2e2bf0ce0
            if let Some(max_len) = max_len {
                length = min(length, max_len);
            }

            let length =
                if unicode { length as usize * 2 } else { length as usize };

            let (remainder, string) = take(length)(string)?;

            let string = if unicode {
                let (_, string) = Self::parse_utf16_string(string)?;
                string
            } else {
                String::from_utf8_lossy(string).to_string()
            };

            Ok((remainder, string))
        }
    }

    fn parse_string(input: &[u8]) -> IResult<&[u8], String> {
        let (remainder, s) = take_while(|c| c != 0)(input)?;
        Ok((remainder, String::from_utf8_lossy(s).to_string()))
    }

    /// Parses null-terminated UTF-16 LE strings.
    ///
    /// Consumes 16-bit values until it reaches a null terminator, then tries
    /// to decode those 16-bit values as a UTF-16 string. The null
    /// terminator is not part of the string and is returned as part of the
    /// remainder. If the end of the input is reached without finding the
    /// null terminator, and the input has an even number of bytes, the
    /// parser tries to decode the whole input as a UTF-16 string.
    ///
    /// Invalid data in UTF-16 strings will be replaced with the [`replacement
    /// character`](std::char::REPLACEMENT_CHARACTER) (U+FFFD).
    fn parse_utf16_string(input: &[u8]) -> IResult<&[u8], String> {
        map_res(
            fold_many0(
                verify(le_u16, |c| *c != 0_u16),
                Vec::new,
                |mut s: Vec<_>, c| {
                    s.push(c);
                    s
                },
            ),
            |s| {
                Ok::<String, nom::error::Error<&[u8]>>(
                    String::from_utf16_lossy(s.as_slice()),
                )
            },
        )
        .parse(input)
    }

    /// Gets a number from the parser `f` and returns a subslice of the input
    /// of size `number - sizeof(number)`.
    ///
    /// Many data structures in a LNK file consists of a block of data that
    /// starts with the block's size, where the size includes the length of the
    /// size field itself. This function is useful for reading such blocks.
    fn length_data<'a, N, F>(
        mut f: F,
    ) -> impl Parser<&'a [u8], Output = &'a [u8], Error = NomError<'a>> + 'a
    where
        N: ToUsize,
        F: Parser<&'a [u8], Output = N, Error = NomError<'a>> + 'a,
    {
        move |input: &'a [u8]| {
            let input_length = input.len();
            let (data, size) = f.parse(input)?;
            // size_len is the length in bytes of the size field, usually
            // 2 or 4 bytes.
            let size_len = input_length - data.len();
            let size: usize = size.to_usize();

            // This should not happen, the size should be at least the
            // length of the size field itself, but it could happen in
            // corrupted files.
            if size < size_len {
                return Err(Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                )));
            }

            if let Some(needed) =
                size.checked_sub(input_length).and_then(NonZeroUsize::new)
            {
                Err(Err::Incomplete(Needed::Size(needed)))
            } else {
                Ok(data.take_split(size - size_len))
            }
        }
    }
}

/// Converts from Window's FILETIME to UNIX timestamp.
///
/// Windows FILETIME is the number 100 nanosecond intervals since
/// 1601-01-01T00:00:00Z, while UNIX epoch is the number of seconds since
/// 1970-01-01T00:00:00Z. UNIX epoch starts 11644473600 seconds after
/// Windows epoch, so the UNIX timestamp is FILETIME in seconds minus
/// 11644473600.
///
/// This function returns None if the given FILETIME is zero or outside the
/// range representable by a UNIX timestamp.
///
/// For details see:
/// https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux
#[inline]
fn filetime_to_unix_timestamp(filetime: u64) -> Option<u64> {
    (filetime / 10000000).checked_sub(11644473600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_unix_timestamp() {
        assert_eq!(filetime_to_unix_timestamp(0), None);
        assert_eq!(filetime_to_unix_timestamp(116444736000000000), Some(0));
        assert_eq!(
            filetime_to_unix_timestamp(116444736000000000 + 10000000),
            Some(1)
        );
    }

    #[test]
    fn test_lnk_parser_invalid() {
        let mut parser = LnkParser::new();
        assert!(parser.parse(b"too short").is_err());
    }
}
