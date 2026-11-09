// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

use std::io::Read;

use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use flate2::{Decompress, FlushDecompress, Status};
use ruzstd::decoding::StreamingDecoder as ZstdDecoder;

use crate::{EwfError, Result};

const MIN_ZSTD_WINDOW_LIMIT: u64 = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkEncoding {
    Raw,
    Zlib,
    Zstd,
    Bzip2,
    PatternFill(u64),
}

pub(crate) fn decode_chunk(
    encoded: &[u8],
    encoding: ChunkEncoding,
    logical_size: usize,
) -> Result<Vec<u8>> {
    decode_chunk_with_padding(encoded, encoding, logical_size, logical_size)
}

pub(crate) fn decode_chunk_with_padding(
    encoded: &[u8],
    encoding: ChunkEncoding,
    logical_size: usize,
    maximum_decoded_size: usize,
) -> Result<Vec<u8>> {
    decode_chunk_with_decoded_length(encoded, encoding, logical_size, maximum_decoded_size)
        .map(|(decoded, _)| decoded)
}

/// Decodes like [`decode_chunk_with_padding`] and also returns how many bytes the
/// encoded data produced before the result was cut to `logical_size`.
pub(crate) fn decode_chunk_with_decoded_length(
    encoded: &[u8],
    encoding: ChunkEncoding,
    logical_size: usize,
    maximum_decoded_size: usize,
) -> Result<(Vec<u8>, usize)> {
    if maximum_decoded_size < logical_size {
        return Err(EwfError::Malformed(
            "decoded chunk size bound is too small".into(),
        ));
    }
    match encoding {
        ChunkEncoding::Raw => {
            if encoded.len() < logical_size {
                return Err(EwfError::Malformed(format!(
                    "raw chunk has {} bytes, expected at least {logical_size}",
                    encoded.len()
                )));
            }
            Ok((encoded[..logical_size].to_vec(), logical_size))
        }
        ChunkEncoding::Zlib => decode_compressed(
            ZlibDecoder::new(encoded),
            logical_size,
            maximum_decoded_size,
        ),
        ChunkEncoding::Zstd => decode_xways_zstd(encoded, logical_size, maximum_decoded_size),
        ChunkEncoding::Bzip2 => {
            decode_compressed(BzDecoder::new(encoded), logical_size, maximum_decoded_size)
        }
        ChunkEncoding::PatternFill(pattern) => {
            Ok((pattern_fill(pattern, logical_size), logical_size))
        }
    }
}

/// Decodes a zlib chunk that must verify itself: the stream has to end, with
/// its Adler-32 matching, exactly at the end of `encoded`. Used for sequentially
/// carved chunks or damaged sector data. This verifies the stored payload,
/// not the logical position assigned to it by a table.
pub(crate) fn decode_zlib_exact(
    encoded: &[u8],
    logical_size: usize,
    maximum_decoded_size: usize,
) -> Result<Vec<u8>> {
    if maximum_decoded_size < logical_size {
        return Err(EwfError::Malformed(
            "decoded chunk size bound is too small".into(),
        ));
    }
    let capacity = maximum_decoded_size
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("logical chunk size overflow".into()))?;
    let mut output = vec![0; capacity];
    let mut decompress = Decompress::new(true);
    let status = decompress
        .decompress(encoded, &mut output, FlushDecompress::Finish)
        .map_err(|err| EwfError::Malformed(format!("chunk decompression failed: {err}")))?;
    let consumed = decompress.total_in();
    let produced = usize::try_from(decompress.total_out())
        .map_err(|_| EwfError::Malformed("decoded chunk size does not fit usize".into()))?;
    if status != Status::StreamEnd
        || u64::try_from(encoded.len()).ok() != Some(consumed)
        || produced < logical_size
        || produced > maximum_decoded_size
    {
        return Err(EwfError::Malformed(format!(
            "chunk is not a complete zlib stream of {logical_size} bytes filling its {} \
             stored bytes",
            encoded.len()
        )));
    }
    output.truncate(logical_size);
    Ok(output)
}

pub(crate) fn validate_encoded_size(
    encoded_size: u64,
    chunk_size: u64,
    encoding: ChunkEncoding,
) -> Result<()> {
    if matches!(encoding, ChunkEncoding::PatternFill(_)) {
        return Ok(());
    }
    if encoded_size == 0 {
        return Err(EwfError::Malformed("chunk data size is zero".into()));
    }

    let cap = match encoding {
        ChunkEncoding::Raw => raw_chunk_size_cap(chunk_size)?,
        ChunkEncoding::Zlib => zlib_compressed_chunk_size_cap(chunk_size)?,
        ChunkEncoding::Zstd => zstd_compressed_chunk_size_cap(chunk_size)?,
        ChunkEncoding::Bzip2 => bzip2_compressed_chunk_size_cap(chunk_size)?,
        ChunkEncoding::PatternFill(_) => unreachable!("handled above"),
    };
    if encoded_size > cap {
        return Err(EwfError::Malformed(format!(
            "encoded chunk size {encoded_size} exceeds maximum {cap}"
        )));
    }
    Ok(())
}

fn decode_xways_zstd(
    encoded: &[u8],
    logical_size: usize,
    maximum_decoded_size: usize,
) -> Result<(Vec<u8>, usize)> {
    if encoded == [0] {
        return Ok((vec![0; logical_size], logical_size));
    }
    if encoded.len() == 1 {
        return Err(EwfError::Malformed(format!(
            "invalid X-Ways zero chunk marker 0x{:02x}",
            encoded[0]
        )));
    }

    const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    let framed = ZSTD_FRAME_MAGIC.as_slice().chain(encoded);
    let max_window_size = u64::try_from(maximum_decoded_size)
        .map_err(|_| EwfError::Malformed("logical chunk size does not fit u64".into()))?
        .max(MIN_ZSTD_WINDOW_LIMIT);
    let decoder =
        ZstdDecoder::new_with_max_window_size(framed, max_window_size).map_err(|err| {
            EwfError::Malformed(format!(
                "chunk Zstandard decoder initialization failed: {err}"
            ))
        })?;
    decode_compressed(decoder, logical_size, maximum_decoded_size)
}

fn decode_compressed(
    mut reader: impl Read,
    logical_size: usize,
    maximum_decoded_size: usize,
) -> Result<(Vec<u8>, usize)> {
    let limit = maximum_decoded_size
        .checked_add(1)
        .ok_or_else(|| EwfError::Malformed("logical chunk size overflow".into()))?;
    let mut decoded = Vec::with_capacity(logical_size);
    reader
        .by_ref()
        .take(limit as u64)
        .read_to_end(&mut decoded)
        .map_err(|err| EwfError::Malformed(format!("chunk decompression failed: {err}")))?;

    if decoded.len() < logical_size || decoded.len() > maximum_decoded_size {
        let expected = if logical_size == maximum_decoded_size {
            logical_size.to_string()
        } else {
            format!("between {logical_size} and {maximum_decoded_size}")
        };
        return Err(EwfError::Malformed(format!(
            "decoded chunk has {} bytes, expected {expected}",
            decoded.len()
        )));
    }
    let decoded_length = decoded.len();
    decoded.truncate(logical_size);
    Ok((decoded, decoded_length))
}

fn pattern_fill(pattern: u64, logical_size: usize) -> Vec<u8> {
    let pattern = pattern.to_le_bytes();
    let mut out = vec![0; logical_size];
    let mut chunks = out.chunks_exact_mut(pattern.len());
    for chunk in &mut chunks {
        chunk.copy_from_slice(&pattern);
    }
    let remainder = chunks.into_remainder();
    remainder.copy_from_slice(&pattern[..remainder.len()]);
    out
}

pub(crate) fn zlib_compressed_chunk_size_cap(chunk_size: u64) -> Result<u64> {
    let compress_bound = chunk_size
        .checked_add(chunk_size >> 12)
        .and_then(|value| value.checked_add(chunk_size >> 14))
        .and_then(|value| value.checked_add(chunk_size >> 25))
        .and_then(|value| value.checked_add(13))
        .ok_or_else(|| EwfError::Malformed("zlib compressed chunk size cap overflow".into()))?;
    let stored_blocks = chunk_size
        .checked_add(511)
        .and_then(|value| value.checked_div(512))
        .ok_or_else(|| EwfError::Malformed("zlib stored block count overflow".into()))?;
    let stored_bound = chunk_size
        .checked_add(
            stored_blocks
                .checked_mul(5)
                .ok_or_else(|| EwfError::Malformed("zlib stored block cap overflow".into()))?,
        )
        .and_then(|value| value.checked_add(6))
        .ok_or_else(|| EwfError::Malformed("zlib stored block cap overflow".into()))?;
    Ok(compress_bound.max(stored_bound))
}

pub(crate) fn zstd_compressed_chunk_size_cap(chunk_size: u64) -> Result<u64> {
    chunk_size
        .checked_mul(2)
        .ok_or_else(|| EwfError::Malformed("Zstandard compressed chunk size cap overflow".into()))
}

fn bzip2_compressed_chunk_size_cap(chunk_size: u64) -> Result<u64> {
    chunk_size
        .checked_add(chunk_size / 100)
        .and_then(|value| value.checked_add(4096))
        .ok_or_else(|| EwfError::Malformed("BZip2 compressed chunk size cap overflow".into()))
}

pub(crate) fn raw_chunk_size_cap(chunk_size: u64) -> Result<u64> {
    chunk_size
        .checked_add(4)
        .ok_or_else(|| EwfError::Malformed("raw chunk size cap overflow".into()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use bzip2::write::BzEncoder;
    use flate2::write::ZlibEncoder;

    use super::*;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn bzip2(data: &[u8]) -> Vec<u8> {
        let mut encoder = BzEncoder::new(Vec::new(), bzip2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn raw_decode_returns_logical_prefix_and_ignores_checksum_trailer() {
        let decoded = decode_chunk(b"hello\xaa\xbb\xcc\xdd", ChunkEncoding::Raw, 5).unwrap();

        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn zlib_decode_returns_exact_logical_size() {
        let encoded = zlib(b"compressed data");

        let decoded = decode_chunk(&encoded, ChunkEncoding::Zlib, "compressed data".len()).unwrap();

        assert_eq!(decoded, b"compressed data");
    }

    #[test]
    fn compressed_logical_tail_accepts_only_bounded_padding() {
        let encoded = zlib(b"content plus padding");
        assert_eq!(
            decode_chunk_with_padding(&encoded, ChunkEncoding::Zlib, 7, 32).unwrap(),
            b"content"
        );
        assert!(decode_chunk_with_padding(&encoded, ChunkEncoding::Zlib, 7, 18).is_err());
        assert!(decode_chunk_with_padding(&encoded, ChunkEncoding::Zlib, 30, 32).is_err());
        assert!(decode_chunk(&encoded, ChunkEncoding::Zlib, 7).is_err());
    }

    #[test]
    fn exact_zlib_decode_requires_the_whole_stream_and_its_checksum() {
        let encoded = zlib(b"verified chunk");
        assert_eq!(
            decode_zlib_exact(&encoded, 14, 14).unwrap(),
            b"verified chunk"
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_zlib_exact(&trailing, 14, 14).is_err());
        assert!(decode_zlib_exact(&encoded[..encoded.len() - 1], 14, 14).is_err());
        let mut damaged = encoded.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(decode_zlib_exact(&damaged, 14, 14).is_err());
        assert!(decode_zlib_exact(&encoded, 13, 13).is_err());
        assert_eq!(decode_zlib_exact(&encoded, 7, 14).unwrap(), b"verifie");
    }

    #[test]
    fn bzip2_decode_returns_exact_logical_size() {
        let encoded = bzip2(b"bzip2 data");

        let decoded = decode_chunk(&encoded, ChunkEncoding::Bzip2, "bzip2 data".len()).unwrap();

        assert_eq!(decoded, b"bzip2 data");
    }

    #[test]
    fn pattern_fill_repeats_little_endian_pattern() {
        let decoded =
            decode_chunk(&[], ChunkEncoding::PatternFill(0x1122_3344_5566_7788), 10).unwrap();

        assert_eq!(
            decoded,
            vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77]
        );
    }

    #[test]
    fn raw_decode_rejects_short_input() {
        let err = decode_chunk(b"abc", ChunkEncoding::Raw, 4).unwrap_err();

        assert!(matches!(err, EwfError::Malformed(_)));
    }

    #[test]
    fn compressed_decode_rejects_truncated_output() {
        let encoded = zlib(b"abc");
        let err = decode_chunk(&encoded, ChunkEncoding::Zlib, 4).unwrap_err();

        assert!(matches!(err, EwfError::Malformed(_)));
    }

    #[test]
    fn validate_encoded_size_allows_pattern_fill_without_bytes() {
        validate_encoded_size(0, 32_768, ChunkEncoding::PatternFill(0)).unwrap();
    }

    #[test]
    fn validate_encoded_size_rejects_zero_non_pattern_chunks() {
        let err = validate_encoded_size(0, 32_768, ChunkEncoding::Zlib).unwrap_err();

        assert!(matches!(err, EwfError::Malformed(_)));
    }

    #[test]
    fn validate_encoded_size_rejects_zlib_above_cap() {
        let err = validate_encoded_size(40_000, 32_768, ChunkEncoding::Zlib).unwrap_err();

        assert!(matches!(err, EwfError::Malformed(_)));
    }

    #[test]
    fn validate_encoded_size_allows_stored_deflate_blocks() {
        validate_encoded_size(33_036, 32_768, ChunkEncoding::Zlib).unwrap();
    }

    #[test]
    fn validate_encoded_size_allows_larger_bzip2_cap() {
        validate_encoded_size(35_000, 32_768, ChunkEncoding::Bzip2).unwrap();
    }
}
