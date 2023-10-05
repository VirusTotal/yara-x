use std::mem;
use std::num::NonZeroUsize;

use nom::bytes::complete::{take, take_while};
use nom::combinator::{cond, map, map_res, verify};
use nom::multi::{fold_many0, length_value, many_till};
use nom::number::complete::{le_u128, le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::{Err, ToUsize};
use nom::{IResult, InputLength, InputTake, Needed, Parser};

use crate::modules::protos::lnk::{ItemId, Lnk};

/// A Windows LNK file parser.
pub(crate) struct LnkParser {
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
                file_attribute_flags,
                creation_time,
                access_time,
                write_time,
                file_size,
                icon_index,
                show_command,
                hotkey_flags,
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
                clsid == 0x46000000_000000C0_00000000_00021401
            }),
            le_u32, // link_flags,
            le_u32, // file_attribute_flags
            le_u64, // creation_time
            le_u64, // access_time
            le_u64, // write_time
            le_u32, // file_size
            le_u32, // icon_index
            le_u32, // show_command
            le_u16, // hotkey_flags
            le_u16, // reserved
            le_u32, // reserved
            le_u32, // reserved
        ))
        .parse(input)?;

        self.result.is_lnk = Some(true);
        self.result.file_attribute_flags = Some(file_attribute_flags);
        self.result.creation_time = filetime_to_unix_timestamp(creation_time);
        self.result.access_time = filetime_to_unix_timestamp(access_time);
        self.result.write_time = filetime_to_unix_timestamp(write_time);
        self.result.file_size = Some(file_size);
        self.result.icon_index = Some(icon_index);
        self.result.show_command = Some(show_command);
        self.result.hotkey_flags = Some(hotkey_flags.into());

        let unicode = link_flags & Self::IS_UNICODE != 0;

        // Parse the link target list (LINKTARGET_IDLIST), if present.
        //
        // IDLIST = *ITEMID TERMINALID
        if link_flags & Self::HAS_LINK_TARGET_ID_LIST != 0 {
            (input, _) = self.parse_link_target_id_list(input)?
        };

        // Parse the link info (LINKINFO), if present.
        if link_flags & Self::HAS_LINK_INFO != 0 {
            (input, _) = self.parse_link_info(input)?;
        };

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

        (input, self.result.arguments) = cond(
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
        if overlay.len() > 0 {
            self.result.overlay_offset =
                Some((total_size - overlay.len()).try_into().unwrap());
        }

        self.result.overlay_size = Some(overlay.len().try_into().unwrap());

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

    fn parse_link_info<'a>(
        &mut self,
        input: &'a [u8],
    ) -> IResult<&'a [u8], ()> {
        let (
            optional_fields,
            (
                size,
                header_size,
                flags,
                volume_id_offset,
                local_base_path_offset,
                common_network_relative_link_offset,
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
                self.parse_volume_id(d)?;
            }
            match local_base_path_offset_unicode {
                Some(offset) if offset > 0 => {
                    if let Some(string) = link_info.get(offset as usize..) {
                        let (_, path) = Self::parse_utf16_string(string)?;
                        self.result.local_base_path = Some(path);
                    }
                }
                _ => {
                    if let Some(string) =
                        link_info.get(local_base_path_offset as usize..)
                    {
                        let (_, path) = Self::parse_string(string)?;
                        self.result.local_base_path = Some(path);
                    }
                }
            }
        }

        if flags & Self::COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX != 0 {
            match common_path_suffix_offset_unicode {
                Some(offset) if offset > 0 => {
                    if let Some(string) = link_info.get(offset as usize..) {
                        let (_, path) = Self::parse_utf16_string(string)?;
                        self.result.common_path_suffix = Some(path);
                    }
                }
                _ => {
                    if let Some(string) =
                        link_info.get(common_path_suffix_offset as usize..)
                    {
                        let (_, path) = Self::parse_string(string)?;
                        self.result.common_path_suffix = Some(path);
                    }
                }
            }
        }

        Ok((remainder, ()))
    }

    fn parse_volume_id<'a>(
        &mut self,
        input: &'a [u8],
    ) -> IResult<&'a [u8], ()> {
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

        self.result.drive_type = Some(drive_type);
        self.result.drive_serial_number = Some(drive_serial_number);

        // The volume ID struct takes the first `volume_id_size` bytes of
        // `input`.
        let (remainder, volume_id) = take(volume_id_size)(input)?;

        // According to the specification if volume_label_offset is 0x14 it
        // indicates that the volume label is an unicode string. In such cases
        // the value of volume_label_offset must be ignored, and the offset
        // to the unicode string is the 4 bytes offset that comes right after
        // `volume_label_offset`.
        if volume_label_offset == 0x14 {
            (_, volume_label_offset) = le_u32(optional)?;
            if let Some(d) = volume_id.get(volume_label_offset as usize..) {
                let (_, volume_label) = Self::parse_utf16_string(d)?;
                // TODO: implement a protobuf type for representing strings
                // contained within the scanned data that doesn't need copying
                // data.
                self.result.volume_label = Some(volume_label);
            }
        } else if let Some(d) = input.get(volume_label_offset as usize..) {
            let (_, volume_label) = Self::parse_string(d)?;
            self.result.volume_label = Some(volume_label);
        }

        Ok((remainder, ()))
    }

    fn parse_link_target_id_list<'a>(
        &mut self,
        input: &'a [u8],
    ) -> IResult<&'a [u8], ()> {
        let (input, item_ids) = length_value(
            le_u16,
            map(
                many_till(
                    // Each item ID starts with a 2-bytes length that includes
                    // the length itself its data.
                    |input: &'a [u8]| {
                        let (remainder, data) =
                            Self::length_data(le_u16)(input)?;

                        let mut result = ItemId::new();

                        // TODO: implement a protobuf type for representing
                        // strings contained within the
                        // scanned data that doesn't need copying
                        // data.
                        result.size = Some(data.len().try_into().unwrap());
                        result.data = Some(data.into());

                        Ok((remainder, result))
                    },
                    // An item ID with size 0 is the terminal one.
                    verify(le_u16, |size| *size == 0),
                ),
                |(item_ids, _terminal)| item_ids,
            ),
        )(input)?;

        for item in item_ids {
            self.result.link_target_id_list.push(item);
        }

        Ok((input, ()))
    }

    /// Gets a number from the parser `f` and returns a subslice of the input
    /// of size `number - sizeof(number)`.
    ///
    /// Many data structures in a LNK file consists of a block of data that
    /// starts with the block's size, where the size includes the length of the
    /// size field itself. This function is useful for reading such blocks.
    pub fn length_data<'a, N, F>(
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

            if let Some(needed) =
                size.checked_sub(input.input_len()).and_then(NonZeroUsize::new)
            {
                Err(Err::Incomplete(Needed::Size(needed)))
            } else {
                Ok(data.take_split(size - size_len))
            }
        }
    }

    fn parse_extra_data_block(
        &mut self,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], ()> + '_ {
        move |input: &[u8]| {
            let (remainder, data) = Self::length_data(le_u32)(input)?;
            Ok((remainder, ()))
        }
    }

    fn parse_string_data(
        unicode: bool,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], Vec<u8>> {
        move |input: &[u8]| {
            let (string, mut length) = le_u16(input)?;

            if unicode {
                length *= 2;
            };

            let (remainder, string) = take(length)(string)?;

            let string = if unicode {
                let (_, string) = Self::parse_utf16_string(string)?;
                string
            } else {
                string.to_vec()
            };

            Ok((remainder, string))
        }
    }

    fn parse_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let (remainder, s) = take_while(|c| c != 0)(input)?;
        Ok((remainder, s.to_vec()))
    }

    /// Parses null-terminated UTF-16 LE strings.
    ///
    /// Consumes 16-bit values until it reaches a null terminator, then tries
    /// to decode those 16-bit values as an UTF-16 string. The null
    /// terminator is not part of the string and is returned as part of the
    /// remainder. If the end of the input is reached without finding the
    /// null terminator, and the input has an even number of bytes, the
    /// parser tries to decode the whole input as a UTF-16 string.
    ///
    /// Invalid data in UTF-16 strings will be replaced with the [`replacement
    /// character`](std::char::REPLACEMENT_CHARACTER) (U+FFFD).
    fn parse_utf16_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
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
                Ok::<Vec<u8>, nom::error::Error<&[u8]>>(
                    String::from_utf16_lossy(s.as_slice()).into_bytes(),
                )
            },
        )(input)
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
