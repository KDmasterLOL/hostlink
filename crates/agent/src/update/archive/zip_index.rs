use super::super::invalid;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_LOCAL_SIGNATURE: u32 = 0x0403_4b50;

/// Validate the small, single-disk, non-ZIP64 package index before `ZipArchive` can
/// normalize duplicate central-directory names into its filename-keyed map.
pub(super) fn validate_central_directory(
    archive: &mut File,
    archive_size: u64,
    expected_names: &[String],
) -> io::Result<()> {
    const EOCD_SIZE: u64 = 22;
    const CENTRAL_HEADER_SIZE: u64 = 46;
    if archive_size < EOCD_SIZE || expected_names.len() > usize::from(u16::MAX) {
        return Err(invalid(
            "Agent ZIP has an unsupported archive size or member count",
        ));
    }

    let mut signature = [0_u8; 4];
    archive.seek(SeekFrom::Start(0))?;
    archive.read_exact(&mut signature)?;
    if read_u32(&signature) != ZIP_LOCAL_SIGNATURE {
        return Err(invalid(
            "Agent ZIP has an unsupported prefix or local header",
        ));
    }

    let eocd_offset = archive_size
        .checked_sub(EOCD_SIZE)
        .ok_or_else(|| invalid("Agent ZIP end record is missing"))?;
    archive.seek(SeekFrom::Start(eocd_offset))?;
    let mut eocd = [0_u8; 22];
    archive.read_exact(&mut eocd)?;
    if read_u32(&eocd[0..4]) != ZIP_EOCD_SIGNATURE
        || read_u16(&eocd[4..6]) != 0
        || read_u16(&eocd[6..8]) != 0
        || usize::from(read_u16(&eocd[8..10])) != expected_names.len()
        || usize::from(read_u16(&eocd[10..12])) != expected_names.len()
        || read_u16(&eocd[20..22]) != 0
    {
        return Err(invalid(
            "Agent ZIP end record is non-canonical or has an unexpected member count",
        ));
    }
    let central_size = u64::from(read_u32(&eocd[12..16]));
    let central_offset = u64::from(read_u32(&eocd[16..20]));
    if central_size == u64::from(u32::MAX)
        || central_offset == u64::from(u32::MAX)
        || central_offset
            .checked_add(central_size)
            .filter(|end| *end == eocd_offset)
            .is_none()
    {
        return Err(invalid(
            "Agent ZIP central directory bounds are unsupported or inconsistent",
        ));
    }

    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| invalid("Agent ZIP central directory size overflow"))?;
    let mut cursor = central_offset;
    let mut previous_local_offset = None;
    for expected_name in expected_names {
        let header_end = cursor
            .checked_add(CENTRAL_HEADER_SIZE)
            .filter(|end| *end <= central_end)
            .ok_or_else(|| invalid("Agent ZIP central directory is truncated"))?;
        archive.seek(SeekFrom::Start(cursor))?;
        let mut header = [0_u8; 46];
        archive.read_exact(&mut header)?;
        if read_u32(&header[0..4]) != ZIP_CENTRAL_SIGNATURE {
            return Err(invalid("Agent ZIP central directory has an invalid record"));
        }
        let compressed_size = read_u32(&header[20..24]);
        let uncompressed_size = read_u32(&header[24..28]);
        let name_size = u64::from(read_u16(&header[28..30]));
        let extra_size = u64::from(read_u16(&header[30..32]));
        let comment_size = u64::from(read_u16(&header[32..34]));
        let disk_start = read_u16(&header[34..36]);
        let local_offset = u64::from(read_u32(&header[42..46]));
        let variable_end = header_end
            .checked_add(name_size)
            .and_then(|end| end.checked_add(extra_size))
            .and_then(|end| end.checked_add(comment_size))
            .filter(|end| *end <= central_end)
            .ok_or_else(|| invalid("Agent ZIP central record fields exceed directory bounds"))?;
        if name_size == 0
            || disk_start != 0
            || compressed_size == u32::MAX
            || uncompressed_size == u32::MAX
            || local_offset == u64::from(u32::MAX)
            || previous_local_offset.is_some_and(|previous| local_offset <= previous)
        {
            return Err(invalid("Agent ZIP uses an unsupported central record"));
        }
        let name_len = usize::try_from(name_size)
            .map_err(|_| invalid("Agent ZIP member name size is unsupported"))?;
        let mut name = vec![0_u8; name_len];
        archive.read_exact(&mut name)?;
        if name.as_slice() != expected_name.as_bytes() {
            return Err(invalid(
                "Agent ZIP central member names or order do not match the package contract",
            ));
        }
        let extra_len = usize::try_from(extra_size)
            .map_err(|_| invalid("Agent ZIP extra field size is unsupported"))?;
        let mut extra = vec![0_u8; extra_len];
        archive.read_exact(&mut extra)?;
        validate_non_zip64_extra_fields(&extra)?;

        let local_fixed_end = local_offset
            .checked_add(30)
            .filter(|end| *end <= central_offset)
            .ok_or_else(|| invalid("Agent ZIP local header offset is invalid"))?;
        archive.seek(SeekFrom::Start(local_offset))?;
        let mut local_header = [0_u8; 30];
        archive.read_exact(&mut local_header)?;
        if read_u32(&local_header[0..4]) != ZIP_LOCAL_SIGNATURE
            || (previous_local_offset.is_none() && local_offset != 0)
        {
            return Err(invalid(
                "Agent ZIP contains a prefix or invalid local header",
            ));
        }
        let local_name_size = usize::from(read_u16(&local_header[26..28]));
        let local_extra_size = usize::from(read_u16(&local_header[28..30]));
        let local_fields_size = local_name_size
            .checked_add(local_extra_size)
            .ok_or_else(|| invalid("Agent ZIP local header field size overflow"))?;
        let local_variable_end = local_fixed_end
            .checked_add(
                u64::try_from(local_fields_size)
                    .map_err(|_| invalid("Agent ZIP local header field size is unsupported"))?,
            )
            .filter(|end| *end <= central_offset)
            .ok_or_else(|| invalid("Agent ZIP local header fields exceed archive bounds"))?;
        if read_u32(&local_header[18..22]) == u32::MAX
            || read_u32(&local_header[22..26]) == u32::MAX
            || local_name_size != name_len
        {
            return Err(invalid("Agent ZIP local header uses unsupported fields"));
        }
        let mut local_name = vec![0_u8; local_name_size];
        archive.read_exact(&mut local_name)?;
        if local_name != name {
            return Err(invalid("Agent ZIP local and central names do not match"));
        }
        let mut local_extra = vec![0_u8; local_extra_size];
        archive.read_exact(&mut local_extra)?;
        validate_non_zip64_extra_fields(&local_extra)?;
        local_variable_end
            .checked_add(u64::from(compressed_size))
            .filter(|end| *end <= central_offset)
            .ok_or_else(|| invalid("Agent ZIP member data exceeds archive bounds"))?;
        previous_local_offset = Some(local_offset);
        cursor = variable_end;
    }
    if cursor != central_end {
        return Err(invalid(
            "Agent ZIP central directory contains hidden or trailing records",
        ));
    }
    Ok(())
}

fn validate_non_zip64_extra_fields(mut fields: &[u8]) -> io::Result<()> {
    while !fields.is_empty() {
        if fields.len() < 4 {
            return Err(invalid("Agent ZIP extra field is truncated"));
        }
        let field_id = read_u16(&fields[0..2]);
        let field_size = usize::from(read_u16(&fields[2..4]));
        fields = &fields[4..];
        if field_id == 0x0001 || field_size > fields.len() {
            return Err(invalid("Agent ZIP has a ZIP64 or malformed extra field"));
        }
        fields = &fields[field_size..];
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
