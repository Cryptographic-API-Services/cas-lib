use std::io::Cursor;

/// Compresses data using Zstandard compression algorithm.
/// The `level` parameter controls the compression level (0-22).
/// Higher levels result in better compression but slower performance.
pub fn compress(data_to_compress: Vec<u8>, level: i32) -> Vec<u8> {
    let cursor = Cursor::new(data_to_compress);
    let mut compressed_data = Vec::new();
    zstd::stream::copy_encode(cursor, &mut compressed_data, level).unwrap();
    compressed_data
}

/// Decompresses data using Zstandard decompression algorithm.
pub fn decompress(data_to_decompress: Vec<u8>) -> Vec<u8> {
    let mut cursor = Cursor::new(data_to_decompress);
    let mut decompressed_data = Vec::new();
    zstd::stream::copy_decode(&mut cursor, &mut decompressed_data).unwrap();
    decompressed_data
}