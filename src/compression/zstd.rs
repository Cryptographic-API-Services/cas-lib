use std::io::Cursor;

use crate::error::{CasError, CasResult};

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

/// Decompresses data using Zstandard decompression algorithm.
pub fn decompress(data_to_decompress: Vec<u8>) -> CasResult<Vec<u8>> {
    let mut cursor = Cursor::new(data_to_decompress);
    let mut decompressed_data = Vec::new();
    zstd::stream::copy_decode(&mut cursor, &mut decompressed_data)
        .map_err(|_| CasError::CompressionFailed)?;
    Ok(decompressed_data)
}
