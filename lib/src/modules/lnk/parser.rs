use std::mem;
use std::num::NonZeroUsize;

use nom::bytes::complete::{take, take_while};
use nom::combinator::{cond, map_res, verify};
use nom::multi::{fold_many0, length_value, many_till};
use nom::number::complete::{le_u128, le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::{Err, ToUsize};
use nom::{IResult, InputTake, Needed, Parser};
use protobuf::EnumOrUnknown;
use uuid::Uuid;

use crate::modules::protos::lnk::{DriveType, Lnk, ShowCommand, TrackerData};

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
            mut input,
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
        ) = tuple((
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
        ))
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

        // Parse the link target list (LINKTARGET_IDLIST), if present.
        //
        // IDLIST = *ITEMID TERMINALID
        (input, _) = cond(
            link_flags & Self::HAS_LINK_TARGET_ID_LIST != 0,
            self.parse_link_target_id_list(),
        )(input)?;

        // Parse the link info (LINKINFO), if present.
        (input, _) = cond(
            link_flags & Self::HAS_LINK_INFO != 0,
            self.parse_link_info(),
        )(input)?;

        // Parse the string data (STRING_DATA).
        //
        // STRING_DATA = [NAME_STRING] [RELATIVE_PATH] [WORKING_DIR]
        //               [COMMAND_LINE_ARGUMENTS] [ICON_LOCATION]
        (input, self.result.name) = cond(
            link_flags & Self::HAS_NAME != 0,
            Self::parse_string_data(unicode),
        )(input)?;

        (input, self.result.relative_path) = cond(
            link_flags & Self::HAS_RELATIVE_PATH != 0,
            Self::parse_string_data(unicode),
        )(input)?;

        (input, self.result.working_dir) = cond(
            link_flags & Self::HAS_WORKING_DIR != 0,
            Self::parse_string_data(unicode),
        )(input)?;

        (input, self.result.cmd_line_args) = cond(
            link_flags & Self::HAS_ARGUMENTS != 0,
            Self::parse_string_data(unicode),
        )(input)?;

        (input, self.result.icon_location) = cond(
            link_flags & Self::HAS_ICON_LOCATION != 0,
            Self::parse_string_data(unicode),
        )(input)?;

        // Parse the extra data.
        //
        // EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK
        let (overlay, _) = many_till(
            self.parse_extra_data_block(),
            // The terminal block has size < 4.
            verify(le_u32, |block_size| *block_size < 4),
        )(input)?;

        // Any remaining data is outside the specification and its considered
        // an overlay. The field `overlay_offset` is initialized only if there
        // is some overlay.
        if !overlay.is_empty() {
            self.result.overlay_offset =
                Some((total_size - overlay.len()).try_into().unwrap());
        }

        self.result.overlay_size = overlay.len().try_into().ok();

        Ok(mem::take(&mut self.result))
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
            let (remainder, _) = length_value(
                le_u16,
                many_till(
                    self.parse_link_target_id(),
                    // An item ID with size 0 is the terminal one.
                    verify(le_u16, |size| *size == 0),
                ),
            )(input)?;

            Ok((remainder, ()))
        }
    }

    fn parse_link_target_id(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            // Each item ID starts with a 2-bytes length that includes
            // the length itself its data.
            let (remainder, _data) = Self::length_data(le_u16)(input)?;
            // TODO(vmalvarez): Implement the parsing of link targets if
            // there's enough demand for it.
            // A possible reference implementation is:
            // https://github.com/Matmaus/LnkParse3/blob/master/LnkParse3/target_factory.py#L1
            Ok((remainder, ()))
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
            ) = tuple((
                le_u32, // link_info_size
                le_u32, // link_info_header_size
                le_u32, // link_info_flags,
                le_u32, // volume_id_offset
                le_u32, // local_base_path_offset
                le_u32, // common_network_relative_link_offset
                le_u32, // common_path_suffix_offset
            ))
            .parse(input)?;

            let (
                _,
                (
                    local_base_path_offset_unicode,
                    common_path_suffix_offset_unicode,
                ),
            ) = tuple((
                cond(header_size >= 0x24, le_u32),
                cond(header_size >= 0x24, le_u32),
            ))
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
            ) = tuple((
                le_u32, // volume_id_size
                le_u32, // drive_type
                le_u32, // drive_serial_number
                le_u32, // volume_label_offset
            ))(input)?;

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
                input.get(volume_label_offset as usize..)
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
            let (remainder, block) = Self::length_data(le_u32)(input)?;
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
            ) = tuple((
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
            ))(input)?;

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
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], String> {
        move |input: &[u8]| {
            let (string, length) = le_u16(input)?;

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
        )(input)
    }

    /// Gets a number from the parser `f` and returns a subslice of the input
    /// of size `number - sizeof(number)`.
    ///
    /// Many data structures in a LNK file consists of a block of data that
    /// starts with the block's size, where the size includes the length of the
    /// size field itself. This function is useful for reading such blocks.
    fn length_data<'a, N, F>(
        mut f: F,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], &'a [u8]>
    where
        N: ToUsize,
        F: Parser<&'a [u8], N, nom::error::Error<&'a [u8]>>,
    {
        move |input: &[u8]| {
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
