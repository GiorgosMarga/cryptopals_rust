use crate::set2;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, NewBlockCipher};
use aes::{Aes128, BlockEncrypt};
use base64;
use hex;
use hex::decode;
use std::collections::HashSet;
use std::{
    fs::File,
    io::{BufRead, BufReader, Result},
};

// str_to_vec transforms a string into a vector of bytes.
pub fn str_to_vec(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}
// vec_to_str transforms a vector of bytes into a string
pub fn vec_to_str(v: &Vec<u8>) -> String {
    String::from_utf8_lossy(v).to_string()
}

// base64_to_hex transforms base64 to hex
pub fn base64_to_hex(input: &Vec<u8>) -> Vec<u8> {
    let bytes = base64::decode(input).unwrap();
    let hex_str = hex::encode(bytes).into_bytes();
    hex_str
}

// hex_to_base64 transforms hex to base64
pub fn hex_to_base64(base64_str: Vec<u8>) -> Vec<u8> {
    let bytes = hex::decode(base64_str).unwrap();
    let base64 = base64::encode(bytes).into_bytes();
    base64
}

// hex_decode decodes a hex encoded vector of bytes
pub fn hex_decode(hex: &Vec<u8>) -> Vec<u8> {
    decode(hex).unwrap()
}

// hex_encode encodes to hex
pub fn hex_encode(hex: &Vec<u8>) -> Vec<u8> {
    str_to_vec(&hex::encode(hex))
}

// base64_decode decodes a base64
pub fn base64_decode(base64: &Vec<u8>) -> Vec<u8> {
    base64::decode(base64).unwrap()
}

// single_byte_xor returns the xor of the input with a single byte
pub fn single_byte_xor(buf: &Vec<u8>, b: u8) -> Vec<u8> {
    let mut xor_res = Vec::new();
    for i in 0..buf.len() {
        xor_res.push(buf[i] ^ b)
    }
    xor_res
}

// fixed_xor returns the xor of two vectors of butes
pub fn fixed_xor(b1: &Vec<u8>, b2: &Vec<u8>) -> Vec<u8> {
    assert_eq!(b1.len(), b2.len());
    let mut xored = Vec::new();
    for i in 0..b1.len() {
        xored.push(b1[i] ^ b2[i]);
    }
    xored
}

// decrypt_single_byte_xor brute forces for every byte value to find the decrypted message using the score of it.
pub fn decrypt_single_byte_xor(encrypted: &Vec<u8>) -> (Vec<u8>, u8) {
    let mut best_score = 0;
    let mut message: Vec<u8> = Vec::new();
    let mut key: u8 = 0;
    for i in 0..255 {
        let decrypted_msg = single_byte_xor(encrypted, i);
        let score = get_score(&decrypted_msg);
        if score > best_score {
            best_score = score;
            message = decrypted_msg;
            key = i;
        }
    }
    (message, key)
}

// get_score gets a score of a msg. It calculates how many ascci characters exist.
fn get_score(msg: &Vec<u8>) -> usize {
    msg.iter()
        .filter(|&&byte| {
            byte >= b'a' && byte <= b'z' || byte >= b'A' && byte <= b'Z' || byte == b' '
        })
        .count()
}

pub fn detect_single_char_xor(filename: &str) -> Option<Vec<u8>> {
    let lines = read_file(filename);
    if lines.is_err() {
        println!("{}", lines.unwrap_err());
        return None;
    }
    let mut best_score = 0;
    let mut decrypted_message = Vec::new();
    for line in lines.unwrap() {
        let decoded_line = hex_decode(&str_to_vec(&line));
        let (message, _) = decrypt_single_byte_xor(&decoded_line);
        let score = get_score(&message);
        if best_score < score {
            best_score = score;
            decrypted_message = message;
        }
    }
    Some(decrypted_message)
}
pub fn read_file(filename: &str) -> Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let lines: Result<Vec<String>> = reader.lines().collect();
    lines
}

fn repeating_xor_encryption(msg: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut res = Vec::new();
    let mut ctr = 0;
    for i in 0..msg.len() {
        res.push(msg[i] ^ key[ctr]);
        ctr = (ctr + 1) % key.len();
    }
    res
}
fn hamming_dist(b1: &Vec<u8>, b2: &Vec<u8>) -> usize {
    b1.iter()
        .zip(b2.iter())
        .map(|(&x, &y)| (x ^ y).count_ones() as usize)
        .sum()
}
fn into_blocks(encrypted: &Vec<u8>, key_size: usize) -> Vec<Vec<u8>> {
    encrypted
        .chunks(key_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}
fn transpose(blocks: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let max_cols = blocks.iter().map(|row| row.len()).max().unwrap_or(0);
    let mut transposed: Vec<Vec<u8>> = vec![vec![0; blocks.len()]; max_cols];
    for (i, row) in blocks.into_iter().enumerate() {
        for (j, &b) in row.into_iter().enumerate() {
            transposed[j][i] = b;
        }
    }
    transposed
}
fn find_key_size(encrypted: &Vec<u8>, num_of_keys: usize) -> Vec<(f32, usize)> {
    let mut distances: Vec<(f32, usize)> = Vec::new();

    for key_size in 2..40 {
        let chunks: Vec<&[u8]> = encrypted.chunks(key_size).take(4).collect();
        let mut distance: f32 = 0.0;

        for i in 0..chunks.len() - 1 {
            distance += hamming_dist(&chunks[i].to_vec(), &chunks[i + 1].to_vec()) as f32;
        }

        distance /= key_size as f32;
        distances.push((distance, key_size));
    }
    distances.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    distances[0..num_of_keys].to_vec()
}

fn break_repeating_xor(encrypted: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // will use the best 3 keys.
    let keysizes = find_key_size(&encrypted, 3);
    let mut best_score = 0;
    let mut decrypted_msg: Vec<u8> = Vec::new();
    let mut keys: Vec<u8> = Vec::new();
    for keysize in keysizes {
        let blocks = into_blocks(encrypted, keysize.1);
        let mut key: Vec<u8> = Vec::new();
        let transposed = transpose(&blocks);
        for row in &transposed {
            let (_, k) = decrypt_single_byte_xor(row);
            key.push(k);
        }
        let decrypted = repeating_xor_encryption(encrypted, &key);
        if get_score(&decrypted) > best_score {
            best_score = get_score(&decrypted);
            decrypted_msg = decrypted;
            keys = key
        }
    }
    (decrypted_msg, keys)
}
pub fn decrypt_aes_ecb(encrypted: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    assert_eq!(key.len(), 16, "Key must be 16 bytes long");
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut blocks = Vec::new();
    (0..encrypted.len()).step_by(16).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(&encrypted[x..x + 16]));
    });
    cipher.decrypt_blocks(&mut blocks);
    let decrypted = blocks.iter().flatten().map(|x| *x).collect::<Vec<u8>>();
    set2::pkcs7_unpad(&decrypted)
}
pub fn encrypt_aes_ecb(msg: Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    assert_eq!(key.len(), 16, "Key must be 16 bytes long");
    let msg_len = msg.len();
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let padded = set2::pkcs7_pad(msg, 16);
    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::new();
    (0..msg_len).step_by(16).for_each(|x| {
        let mut block = GenericArray::clone_from_slice(&padded[x..x + 16].to_vec());
        cipher.encrypt_block(&mut block);

        encrypted_blocks.push(block.into_iter().collect::<Vec<u8>>());
    });
    encrypted_blocks
        .iter()
        .flatten()
        .map(|x| *x)
        .collect::<Vec<u8>>()
}
pub fn is_ecb_mode(encrypted: &Vec<u8>) -> bool {
    let mut seen_blocks = HashSet::new();
    for block in encrypted.chunks(16) {
        if !seen_blocks.insert(block) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_challenge_1() {
        let base64 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hex = hex_to_base64(str_to_vec(&base64));
        assert_eq!(hex, str_to_vec(result));
    }
    #[test]
    fn test_challenge_2() {
        let b1 = hex_decode(&str_to_vec("1c0111001f010100061a024b53535009181c"));
        let b2 = hex_decode(&str_to_vec("686974207468652062756c6c277320657965"));
        let result = "746865206b696420646f6e277420706c6179";
        let xor = fixed_xor(&b1, &b2);
        assert_eq!(hex_encode(&xor), str_to_vec(result));
    }

    #[test]
    fn test_challenge_3() {
        let encrypted = hex_decode(&str_to_vec(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        ));
        let (decrypted_msg, _) = decrypt_single_byte_xor(&encrypted);
        assert_eq!(
            vec_to_str(&decrypted_msg),
            "Cooking MC's like a pound of bacon"
        )
    }
    #[test]
    fn test_challenge_4() {
        let decrypted = detect_single_char_xor("challenge4.txt");
        assert_eq!(decrypted.is_some(), true);
        assert_eq!(
            decrypted.unwrap(),
            str_to_vec("Now that the party is jumping\n")
        );
    }
    #[test]
    fn test_challenge_5() {
        let msg_to_encrypt = str_to_vec(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        );
        let key = str_to_vec("ICE");
        let encrypted = repeating_xor_encryption(&msg_to_encrypt, &key);
        assert_eq!(str_to_vec("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"), hex_encode(&encrypted));
    }
    #[test]
    fn test_challenge_6() {
        let b1 = str_to_vec("this is a test");
        let b2 = str_to_vec("wokka wokka!!!");
        let dist = hamming_dist(&b1, &b2);
        assert_eq!(dist, 37);
        let filename = "challenge6.txt";
        let lines = read_file(&filename);
        assert_eq!(lines.is_ok(), true);
        let content = lines.unwrap().join("");
        let decoded = base64_decode(&str_to_vec(&content));
        let (decrypted_msg, key) = break_repeating_xor(&decoded);
        assert_eq!(vec_to_str(&key), "Terminator X: Bring the noise");
        println!("{:?}", vec_to_str(&decrypted_msg));
    }

    #[test]
    fn test_challenge_7() {
        let key = str_to_vec("YELLOW SUBMARINE");
        let filename = "challenge7.txt";
        let lines = read_file(&filename);
        assert_eq!(lines.is_ok(), true);
        let content = lines.unwrap().join("");
        let decoded = base64_decode(&str_to_vec(&content));
        let msg = decrypt_aes_ecb(&decoded, &key);
        println!("{:?}", vec_to_str(&msg));
    }

    #[test]
    fn test_challenge_8() {
        let filename = "challenge8.txt";
        let lines = read_file(&filename);
        assert_eq!(lines.is_ok(), true);
        for line in lines.unwrap() {
            let decoded = hex_decode(&str_to_vec(&line));
            if is_ecb_mode(&decoded) {
                println!("This line is most likely using ECB encryption:");
                println!("{line}")
            }
        }
    }
    #[test]
    fn test_encrypt_decrypt_ecb() {
        let key = str_to_vec("YELLOW SUBMARINE");
        let msg = "12345678912345671234567891234567";
        let encrypted = encrypt_aes_ecb(str_to_vec(&msg), &key);
        println!("{:?}", encrypted);
        assert_eq!(decrypt_aes_ecb(&encrypted, &key), str_to_vec(&msg));
    }
}
