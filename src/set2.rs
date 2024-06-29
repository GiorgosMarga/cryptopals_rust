use crate::set1::{self, base64_decode, is_ecb_mode, str_to_vec, vec_to_str};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::Aes128;
use rand::{distributions::Uniform, Rng};

const CH12_PLAINTEXT: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

const CH12_KEY: &str = "YELLOW SUBMARINE";

pub fn pkcs7_pad(data: Vec<u8>, block_size: usize) -> Vec<u8> {
    if data.len() % block_size == 0 {
        return data;
    }
    let padding = block_size - (data.len() % block_size);
    let mut padded_data = Vec::from(data);
    padded_data.extend(vec![padding as u8; padding]);
    padded_data
}
pub fn pkcs7_unpad(data: &Vec<u8>) -> Vec<u8> {
    let padding = data.last().unwrap();
    if *padding > 16 {
        return Vec::from(&data[..data.len()]);
    }
    let unpadded_len = data.len() - *padding as usize;
    Vec::from(&data[..unpadded_len])
}

fn aes_128_cbc_encryption(data: Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let data_len = data.len();
    let padded = pkcs7_pad(data, 16);
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::new();
    (0..data_len).step_by(16).for_each(|x| {
        let last = encrypted_blocks.last().unwrap_or(&iv);
        let xor = set1::fixed_xor(last, &padded[x..x + 16].to_vec());
        let mut block = GenericArray::clone_from_slice(&xor);
        cipher.encrypt_block(&mut block);

        encrypted_blocks.push(block.into_iter().collect::<Vec<u8>>());
    });
    encrypted_blocks
        .iter()
        .flatten()
        .map(|x| *x)
        .collect::<Vec<u8>>()
}

fn aes_128_cbc_decrypt(data: Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let mut decrypted_blocks: Vec<Vec<u8>> = Vec::new();
    (0..data.len()).step_by(16).for_each(|x| {
        let last = if x == 0 { &iv } else { &data[x - 16..x] };

        // Decrypt AES
        let mut block = GenericArray::clone_from_slice(&data[x..x + 16]);
        cipher.decrypt_block(&mut block);
        let decrypted_block = block.into_iter().collect::<Vec<u8>>();
        let xor_block = set1::fixed_xor(&last.to_vec(), &decrypted_block);
        decrypted_blocks.push(xor_block);
    });

    // Get number of padding bytes applied during encryption & remove padding
    let padding_byte = *decrypted_blocks.last().unwrap().last().unwrap() as usize;
    decrypted_blocks
        .iter()
        .flatten()
        .take(data.len() - padding_byte)
        .map(|x| *x)
        .collect::<Vec<u8>>()
}
fn generate_random_bytes(count: usize) -> Vec<u8> {
    let rng = rand::thread_rng();
    rng.sample_iter(&Uniform::new(0u8, 255))
        .take(count)
        .collect()
}
// returns true if ecb is used
fn encryption_oracle(msg: &Vec<u8>) -> (Vec<u8>, bool) {
    let key = generate_random_bytes(16);
    let before = rand::thread_rng().gen_range(5..=10);
    let after = rand::thread_rng().gen_range(5..=10);
    let mut data = generate_random_bytes(before);
    data.extend(msg);
    data.extend(generate_random_bytes(after));
    let res: Vec<u8>;
    let mode: bool;
    if rand::thread_rng().gen_range(1..=2) == 1 {
        res = set1::encrypt_aes_ecb(data, &key);
        mode = true
    } else {
        let iv = generate_random_bytes(16);
        res = aes_128_cbc_encryption(data, &key, &iv);
        mode = false
    }
    (res, mode)
}

fn ch12_encryption_oracle(msg: &Vec<u8>) -> Vec<u8> {
    let mut new_msg = Vec::new();
    let secret_msg = base64_decode(&str_to_vec(CH12_PLAINTEXT));
    new_msg.extend_from_slice(msg);
    new_msg.extend_from_slice(&secret_msg);

    set1::encrypt_aes_ecb(new_msg, &str_to_vec(&CH12_KEY))
}
fn find_block_size() -> usize {
    let mut msg = str_to_vec("");
    let initial_length = ch12_encryption_oracle(&msg).len();
    loop {
        msg.extend_from_slice(&vec!['A' as u8]);
        let length = ch12_encryption_oracle(&msg).len();
        if length != initial_length {
            return length - initial_length;
        }
    }
}

fn is_ecb(block_size: usize) -> bool {
    let msg = vec!['A' as u8; block_size * 3];
    let res = ch12_encryption_oracle(&msg);
    is_ecb_mode(&res)
}

fn ch12_decrypt_ecb() {
    let block_size = find_block_size();
    println!("Blocksize {block_size}");
    let mut secret = str_to_vec("");
    let length = ch12_encryption_oracle(&str_to_vec("")).len();
    let mut check_size = block_size;
    for _ in 0..length {
        let mut padding = vec!['X' as u8; block_size - 1 - (secret.len() % block_size)];
        let known_block: Vec<u8> = ch12_encryption_oracle(&padding);
        padding.extend_from_slice(&secret);
        padding.extend_from_slice(&[10]);
        for b in 0..256 {
            padding[check_size - 1] = b as u8;
            let guessed = ch12_encryption_oracle(&padding);
            if guessed[..check_size] == known_block[..check_size] {
                secret.extend_from_slice(&[b as u8]);
                break;
            }
        }
        if secret.len() % block_size == 0 {
            check_size += block_size
        }
    }
    println!("Secret {:?}", vec_to_str(&pkcs7_unpad(&secret)));
}

#[cfg(test)]
mod tests {

    use set1::{base64_decode, decrypt_aes_ecb, hex_encode, vec_to_str};

    use crate::set1::str_to_vec;

    use super::*;
    #[test]
    fn test_challenge_9() {
        let text = "YELLOW SUBMARINE";
        let result = "YELLOW SUBMARINE\x04\x04\x04\x04";
        let padded = pkcs7_pad(str_to_vec(text), 20);
        assert_eq!(str_to_vec(result), padded);
        assert_eq!(str_to_vec(text), pkcs7_unpad(&padded));
    }
    #[test]
    fn test_challenge_10() {
        let key = str_to_vec("YELLOW SUBMARINE");
        let iv = str_to_vec("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        let filename = "challenge10.txt";
        let lines = set1::read_file(&filename);
        assert_eq!(lines.is_ok(), true);

        let data = lines.unwrap().join("");
        let decoded_data = base64_decode(&str_to_vec(&data));
        let decrypted = aes_128_cbc_decrypt(decoded_data, &key, &iv);
        println!("{:?}", vec_to_str(&decrypted));
    }

    #[test]
    fn test_challenge_12() {
        ch12_decrypt_ecb();
    }
}
