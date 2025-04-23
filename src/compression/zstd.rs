use std::{io::Cursor, sync::mpsc};

pub fn compress(data_to_compress: Vec<u8>, level: i32) -> Vec<u8> {
    let cursor = Cursor::new(data_to_compress);
    let mut compressed_data = Vec::new();
    zstd::stream::copy_encode(cursor, &mut compressed_data, level).unwrap();
    compressed_data
}

pub fn compress_threadpool(data_to_compress: Vec<u8>, level: i32) -> Vec<u8> {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let compressed_data = compress(data_to_compress, level);
        sender.send(compressed_data).unwrap();
    });
    let result = receiver.recv().unwrap();
    result
}

pub fn decompress(data_to_decompress: Vec<u8>) -> Vec<u8> {
    let mut cursor = Cursor::new(data_to_decompress);
    let mut decompressed_data = Vec::new();
    zstd::stream::copy_decode(&mut cursor, &mut decompressed_data).unwrap();
    decompressed_data
}

pub fn decompress_threadpool(data_to_decompress: Vec<u8>) -> Vec<u8> {
    let (sender, receiver) = mpsc::channel();
        rayon::spawn(move || {
            let decompressed_data = decompress(data_to_decompress);
            sender.send(decompressed_data).unwrap();
        });
        let result = receiver.recv().unwrap();
        result
}
