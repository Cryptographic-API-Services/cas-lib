use std::io::{Cursor, Read};

use crate::error::{CasError, CasResult};

/// The largest output, in bytes, that [`decompress`] will produce: 64 MiB.
///
/// A few kilobytes of crafted Zstandard input can expand to many gigabytes. Without a
/// cap, the allocation eventually fails and Rust aborts the whole process, which no
/// FFI caller can catch. Use [`decompress_with_limit`] to choose a different cap.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// The largest back-reference window, as a power of two, a frame may declare: 2^27
/// bytes (128 MiB).
///
/// The decoder allocates the window a frame asks for before producing any output, so
/// this bounds that allocation independently of the output limit. 27 is also
/// Zstandard's own default decoder limit; setting it here keeps the bound if that
/// default ever changes.
const MAX_WINDOW_LOG: u32 = 27;

/// Compresses data using Zstandard compression algorithm.
/// The `level` parameter controls the compression level (0-22).
/// Higher levels result in better compression but slower performance.
pub fn compress(data_to_compress: Vec<u8>, level: i32) -> CasResult<Vec<u8>> {
    let cursor = Cursor::new(data_to_compress);
    let mut compressed_data = Vec::new();
    zstd::stream::copy_encode(cursor, &mut compressed_data, level)
        .map_err(|_| CasError::CompressionFailed)?;
    Ok(compressed_data)
}

/// Decompresses Zstandard data, producing at most [`DEFAULT_MAX_DECOMPRESSED_SIZE`]
/// (64 MiB) of output.
///
/// Returns [`CasError::DecompressionLimitExceeded`] if the data would decompress to
/// more than that, and [`CasError::CompressionFailed`] if it is not valid Zstandard
/// data or declares a window larger than 128 MiB. Use [`decompress_with_limit`] for
/// larger outputs.
pub fn decompress(data_to_decompress: Vec<u8>) -> CasResult<Vec<u8>> {
    decompress_with_limit(data_to_decompress, DEFAULT_MAX_DECOMPRESSED_SIZE)
}

/// Decompresses Zstandard data, producing at most `max_output_size` bytes.
///
/// Decoding stops as soon as the output would exceed `max_output_size`, so a
/// decompression bomb uses at most about `max_output_size` bytes of memory for the
/// output plus the frame's window (capped at 128 MiB). Choose a limit no larger than
/// the biggest output you expect from the data's source.
///
/// Returns [`CasError::DecompressionLimitExceeded`] if the data would decompress to
/// more than `max_output_size` bytes, and [`CasError::CompressionFailed`] if it is not
/// valid Zstandard data or declares a window larger than 128 MiB. Concatenated frames
/// are decoded in sequence and count toward the same limit.
pub fn decompress_with_limit(data_to_decompress: Vec<u8>, max_output_size: usize) -> CasResult<Vec<u8>> {
    let mut decoder = zstd::stream::read::Decoder::with_buffer(&data_to_decompress[..])
        .map_err(|_| CasError::CompressionFailed)?;
    decoder
        .window_log_max(MAX_WINDOW_LOG)
        .map_err(|_| CasError::CompressionFailed)?;

    // Read one byte past the limit: getting it means the output is too large.
    let read_limit = (max_output_size as u64).saturating_add(1);
    let mut decompressed_data = Vec::new();
    decoder
        .take(read_limit)
        .read_to_end(&mut decompressed_data)
        .map_err(|_| CasError::CompressionFailed)?;

    if decompressed_data.len() > max_output_size {
        return Err(CasError::DecompressionLimitExceeded);
    }
    Ok(decompressed_data)
}
