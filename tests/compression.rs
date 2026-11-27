#[cfg(test)]
mod compression {
    use std::io::Write;

    use cas_lib::compression::zstd::{
        compress, decompress, decompress_with_limit, DEFAULT_MAX_DECOMPRESSED_SIZE,
    };
    use cas_lib::error::CasError;

    /// Streams `len` zero bytes through the encoder without holding them in memory, so a
    /// test can build a small input that decompresses to far more than any limit.
    fn compressed_zeros(len: usize, window_log: Option<u32>) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        if let Some(window_log) = window_log {
            encoder.window_log(window_log).unwrap();
        }
        let chunk = vec![0u8; 1024 * 1024];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            encoder.write_all(&chunk[..n]).unwrap();
            remaining -= n;
        }
        encoder.finish().unwrap()
    }

    #[test]
    pub fn test_compression() {

        let original_data = b"Hello, world! This is a test of the compression and decompression functionality.";

        // Compress the data
        let compressed_data: Vec<u8> = compress(original_data.to_vec(), 9).unwrap();
        assert!(!compressed_data.is_empty(), "Compressed data should not be empty");
        assert!(compressed_data.len() < original_data.len(), "Compressed data should be smaller than original data");

        // Decompress the data
        let decompressed_data: Vec<u8> = decompress(compressed_data).unwrap();
        assert_eq!(decompressed_data, original_data.to_vec(), "Decompressed data should match original data");
    }

    #[test]
    pub fn default_limit_is_64_mib() {
        assert_eq!(DEFAULT_MAX_DECOMPRESSED_SIZE, 64 * 1024 * 1024);
    }

    #[test]
    pub fn decompress_rejects_a_decompression_bomb() {
        // 256 MiB of zeros compresses to a few KiB. decompress must stop at the 64 MiB
        // default and return an error instead of allocating the whole output.
        let bomb = compressed_zeros(256 * 1024 * 1024, None);
        assert!(bomb.len() < 64 * 1024, "the bomb should be tiny, got {} bytes", bomb.len());
        assert_eq!(decompress(bomb), Err(CasError::DecompressionLimitExceeded));
    }

    #[test]
    pub fn decompress_accepts_output_exactly_at_the_default_limit() {
        let data = compressed_zeros(DEFAULT_MAX_DECOMPRESSED_SIZE, None);
        let decompressed = decompress(data).unwrap();
        assert_eq!(decompressed.len(), DEFAULT_MAX_DECOMPRESSED_SIZE);
    }

    #[test]
    pub fn decompress_rejects_one_byte_over_the_default_limit() {
        let data = compressed_zeros(DEFAULT_MAX_DECOMPRESSED_SIZE + 1, None);
        assert_eq!(decompress(data), Err(CasError::DecompressionLimitExceeded));
    }

    #[test]
    pub fn decompress_with_limit_enforces_the_exact_boundary() {
        let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let compressed = compress(original.clone(), 3).unwrap();

        assert_eq!(decompress_with_limit(compressed.clone(), 4096).unwrap(), original);
        assert_eq!(
            decompress_with_limit(compressed.clone(), 4095),
            Err(CasError::DecompressionLimitExceeded)
        );
        assert_eq!(
            decompress_with_limit(compressed, 0),
            Err(CasError::DecompressionLimitExceeded)
        );
    }

    #[test]
    pub fn decompress_with_limit_allows_larger_outputs_when_asked() {
        let len = DEFAULT_MAX_DECOMPRESSED_SIZE + 1024;
        let data = compressed_zeros(len, None);
        assert_eq!(decompress_with_limit(data, len).unwrap().len(), len);
    }

    #[test]
    pub fn decompress_with_limit_handles_the_largest_limit() {
        // max_output_size + 1 must not overflow.
        let compressed = compress(b"abc".to_vec(), 3).unwrap();
        assert_eq!(decompress_with_limit(compressed, usize::MAX).unwrap(), b"abc".to_vec());
    }

    #[test]
    pub fn empty_input_round_trips_with_a_zero_limit() {
        let compressed = compress(Vec::new(), 3).unwrap();
        assert_eq!(decompress_with_limit(compressed, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    pub fn concatenated_frames_share_one_limit() {
        // Each frame is under the limit on its own, but together they exceed it.
        let mut two_frames = compress(vec![7u8; 600], 3).unwrap();
        two_frames.extend(compress(vec![9u8; 600], 3).unwrap());

        let mut expected = vec![7u8; 600];
        expected.extend(vec![9u8; 600]);
        assert_eq!(decompress_with_limit(two_frames.clone(), 1200).unwrap(), expected);
        assert_eq!(
            decompress_with_limit(two_frames, 1000),
            Err(CasError::DecompressionLimitExceeded)
        );
    }

    #[test]
    pub fn frames_declaring_a_window_over_128_mib_are_rejected() {
        // A 2^28-byte window is above the 2^27 cap, so the decoder refuses the frame
        // before allocating the window, even though the output itself is tiny.
        let data = compressed_zeros(1024, Some(28));
        assert_eq!(
            decompress_with_limit(data, usize::MAX),
            Err(CasError::CompressionFailed)
        );
    }

    /// The payload behind [`FRAME_FROM_ZSTD_0_13`].
    fn zstd_0_13_fixture_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        for i in 0..64u32 {
            payload.extend_from_slice(
                format!("cas-lib zstd fixture line {i:02}: compressed by the zstd 0.13 stack\n")
                    .as_bytes(),
            );
        }
        payload.extend(0u8..=255);
        payload
    }

    /// `compress(zstd_0_13_fixture_payload(), 3)` as produced by cas-lib 0.7.1, which
    /// used zstd 0.13.6 / zstd-safe 7.4.2 / zstd-sys 2.2.0+zstd.1.6.0. Data compressed
    /// by earlier releases must keep decompressing after a zstd upgrade (#170).
    const FRAME_FROM_ZSTD_0_13: &str = concat!(
        "28b52ffd0058e50d00f4176361732d6c6962207a7374642066697874757265206c696e652030303a20",
        "636f6d7072657373656420627920746865302e313320737461636b0a3132333435363738393130313233",
        "3435363738393230313233343536373839333031323334353637383934303132333435363738393530",
        "313233343536373839363031323300",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "41a811905f9ffd0df0350e127010f8ff06c13308f60f49d0483231491e492699a423c924993c929924",
        "c94792492679493249c68d1b52ae7e4d6515",
    );

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    pub fn frames_compressed_by_the_zstd_0_13_stack_still_decompress() {
        let frame = from_hex(FRAME_FROM_ZSTD_0_13);
        assert_eq!(frame.len(), 453);
        let payload = zstd_0_13_fixture_payload();
        assert_eq!(payload.len(), 4352);

        assert_eq!(decompress(frame.clone()).unwrap(), payload);
        // The limit still applies to old frames.
        assert_eq!(decompress_with_limit(frame.clone(), payload.len()).unwrap(), payload);
        assert_eq!(
            decompress_with_limit(frame, payload.len() - 1),
            Err(CasError::DecompressionLimitExceeded)
        );
    }

    #[test]
    pub fn invalid_input_is_compression_failed() {
        assert_eq!(
            decompress(b"definitely not zstd".to_vec()),
            Err(CasError::CompressionFailed)
        );
        // A valid frame cut short is also an error, not a partial result.
        let mut truncated = compress(vec![1u8; 10_000], 3).unwrap();
        truncated.truncate(truncated.len() - 4);
        assert_eq!(decompress(truncated), Err(CasError::CompressionFailed));
    }
}
