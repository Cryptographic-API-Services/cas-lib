#[cfg(test)]
mod compression {
    use cas_lib::compression::zstd::{compress, decompress};
    #[test]
    pub fn test_compression() {

        let original_data = b"Hello, world! This is a test of the compression and decompression functionality.";
        
        // Compress the data
        let compressed_data: Vec<u8> = compress(original_data.to_vec(), 9);
        assert!(!compressed_data.is_empty(), "Compressed data should not be empty");
        assert!(compressed_data.len() < original_data.len(), "Compressed data should be smaller than original data");

        // Decompress the data
        let decompressed_data: Vec<u8> = decompress(compressed_data);
        assert_eq!(decompressed_data, original_data.to_vec(), "Decompressed data should match original data");
    }
}