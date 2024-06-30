use crate::set1::{self, base64_decode, fixed_xor, is_ecb_mode, str_to_vec, vec_to_str};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::Aes128;
use rand::{distributions::Uniform, Rng};
use std::collections::HashMap;

const CH12_PLAINTEXT: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
const CH12_KEY: &str = "YELLOW SUBMARINE";
const IV: &str = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

// Challenge 9
// pkcs7_pad returns the padded vec.
pub fn pkcs7_pad(data: Vec<u8>, block_size: usize) -> Vec<u8> {
    if data.len() % block_size == 0 {
        return data;
    }
    let padding = block_size - (data.len() % block_size);
    let mut padded_data = Vec::from(data);
    padded_data.extend(vec![padding as u8; padding]);
    padded_data
}
// pkcs7_unpad returns the unpadded vec.
pub fn pkcs7_unpad(data: &Vec<u8>) -> Vec<u8> {
    let padding = data.last().unwrap();
    if *padding > 16 {
        return Vec::from(&data[..data.len()]);
    }
    let unpadded_len = data.len() - *padding as usize;
    Vec::from(&data[..unpadded_len])
}

// Challenge 10
// aes_128_cbc_encryption encrypts a message using CBC.
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
// aes_128_cbc_decrypt decrypts a message using CBC.
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
    let padding_byte = *decrypted_blocks.last().unwrap().last().unwrap() as usize % 16;
    decrypted_blocks
        .iter()
        .flatten()
        .take(data.len() - padding_byte)
        .map(|x| *x)
        .collect::<Vec<u8>>()
}

// Challenge 11
// generate_random_bytes generates 'count' of random bytes.
fn generate_random_bytes(count: usize) -> Vec<u8> {
    let rng = rand::thread_rng();
    rng.sample_iter(&Uniform::new(0u8, 255))
        .take(count)
        .collect()
}
// encryptios_oracle returns either an ECB or CBC encrypted message and true if ECB.
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

// Challenge 12
// ch12_encryption_oracle appends a secret-message to the msg given and uses ECB to encrypt it with a consistent key (CH12_KEY).
fn ch12_encryption_oracle(msg: &Vec<u8>) -> Vec<u8> {
    let mut new_msg = Vec::new();
    let secret_msg = base64_decode(&str_to_vec(CH12_PLAINTEXT));
    new_msg.extend_from_slice(msg);
    new_msg.extend_from_slice(&secret_msg);

    set1::encrypt_aes_ecb(new_msg, &str_to_vec(&CH12_KEY))
}

// find_block_size returns the block size.
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
// is_ecb returns true if the block is encrypted using ECB
fn is_ecb(block_size: usize) -> bool {
    let msg = vec!['A' as u8; block_size * 3];
    let res = ch12_encryption_oracle(&msg);
    is_ecb_mode(&res)
}

// ch12_decrypt_ecb combines the functions above to decrypt the secret-message
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

// Challenge 13
// parser parses a cookie.
fn parser(cookie: &str) -> HashMap<&str, &str> {
    let mut hm = HashMap::new();
    let splitted = cookie.split("&");
    splitted.for_each(|x| {
        let temp: Vec<&str> = x.split("=").collect();
        hm.insert(temp[0].trim(), temp[1].trim());
    });
    hm
}

// object_encoder returns an encoded cookie given an email.
fn object_encoder(email: &str) -> String {
    let email = email.replace("&", "");
    let email = email.replace("=", "");
    let mut encoded = String::from("email=");
    encoded.push_str(email.as_str().trim());
    encoded.push_str("&uid=10&role=user");
    encoded
}

// create_fake_email a useless function that I use to show the process.
fn create_fake_email() -> String {
    // Block that will be encrypted
    // e m a i l = g i o r g o s @ e m   (16)
    // a i l . c o m & u i d = 1 0 & r   (16)
    // o l e = u s e r 8 8 8 8 8 8 8 8   (16)

    // To make the attack the word "user"
    // should be in the last row alone
    // and our fake email should have the word "admin"
    // in it but in a way that makes it again to be alone in a row

    // e m a i l = g i o r g o s @ e m
    // a d m i n <------------------->
    // a i l & u i d = 1 0 & r o l e =
    // u s e r <--------------------->

    // In ecb mode each block will be encrypted so if we swap the order of admin and user block we will get the role=admin

    // So one example is
    String::from("giorgos@emadmin           ail")
}

// Challenge 15
// validate_pkcs_padding returns Some if the block has a valid pkcs7 padding else None.
fn validate_pkcs7_padding(block: &Vec<u8>) -> Option<Vec<u8>> {
    let padding = block.last();
    if padding.is_none() {
        return None;
    }
    let padding = padding.unwrap();
    for i in 16 - padding..16 {
        if block[i as usize] != *padding {
            return None;
        }
    }
    Some(pkcs7_unpad(&block))
}

// Challenge 16
fn url_encode(vec: &Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();

    for byte in vec {
        match byte {
            b'=' => result.extend_from_slice(b"%3D"),
            b';' => result.extend_from_slice(b"%3B"),
            _ => result.push(*byte),
        }
    }

    result
}

// rjust will right align the string, using a specified character as the fill character.
fn rjust(vec: Vec<u8>, width: usize, pad: u8) -> Vec<u8> {
    if vec.len() >= width {
        vec
    } else {
        let mut result = vec![pad; width - vec.len()];
        result.extend(vec);
        result
    }
}
// ljust will left align the string, using a specified character as the fill character.
fn ljust(vec: Vec<u8>, width: usize, pad: u8) -> Vec<u8> {
    if vec.len() >= width {
        vec
    } else {
        let mut result = vec;
        result.extend(vec![pad; width - result.len()]);
        result
    }
}
// wrapper prepends and append to an input. See challenge 16
fn wrapper(input: &Vec<u8>) -> Vec<u8> {
    let encoded_input = url_encode(input);
    let mut str_to_prepend = str_to_vec("comment1=cooking%20MCs;userdata=");
    str_to_prepend.extend_from_slice(&encoded_input);
    str_to_prepend.extend_from_slice(";comment2=%20line%20a%20pound%20of%20bacon".as_bytes());
    aes_128_cbc_encryption(str_to_prepend, &str_to_vec(CH12_KEY), &str_to_vec(IV))
}
// check_admin returns true if the encrypted_msg contains the word admin=true
fn check_admin(encrypted_msg: Vec<u8>) -> bool {
    let dcrypted = aes_128_cbc_decrypt(encrypted_msg, &str_to_vec(CH12_KEY), &str_to_vec(IV));
    let dcrypted = pkcs7_unpad(&dcrypted);
    let decrypted_str = vec_to_str(&dcrypted);
    decrypted_str.contains(";admin=true")
}
// bitflip_attack combines the functions above to attack.
fn bitflip_attack() -> Vec<u8> {
    let block = vec!['X' as u8; 16];
    let encrypted = wrapper(&vec!['X' as u8; 32]);
    let flipper = fixed_xor(&block, &rjust(str_to_vec(";admin=true"), 16, 0));
    let r = rjust(flipper, 16 * 3, 0);
    let padded = ljust(r, encrypted.len(), 0);
    fixed_xor(&encrypted, &padded)
}

#[cfg(test)]
mod tests {

    use set1::{base64_decode, decrypt_aes_ecb, encrypt_aes_ecb, hex_encode, vec_to_str};

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

    #[test]
    fn test_challenge_13() {
        let key = &str_to_vec(CH12_KEY);
        let user_1 = object_encoder(&create_fake_email());
        let encrypted_object = encrypt_aes_ecb(str_to_vec(&user_1), key);
        // swap the blocks. see more in create_fake_email()
        let mut blocks: Vec<Vec<u8>> = encrypted_object.chunks(16).map(|x| x.to_vec()).collect();
        blocks.swap(1, 3);
        let attack_object: Vec<u8> = blocks.into_iter().flatten().collect();
        let decrypted_object = decrypt_aes_ecb(&attack_object, key);
        let strin = vec_to_str(&decrypted_object);
        let object: HashMap<&str, &str> = parser(&strin);
        println!("{:?}", object);
    }
    #[test]
    fn test_challenge_15() {
        let str1 = str_to_vec("ICE ICE BABY\x04\x04\x04\x04");
        assert_eq!(pkcs7_unpad(&str1), validate_pkcs7_padding(&str1).unwrap());
        let str2 = str_to_vec("ICE ICE BABY\x05\x05\x05\x05");
        let str3 = str_to_vec("ICE ICE BABY\x01\x02\x03\x04");
        assert_eq!(true, validate_pkcs7_padding(&str3).is_none());
        assert_eq!(true, validate_pkcs7_padding(&str2).is_none());
    }
    #[test]
    fn test_challenge_16() {
        let input = str_to_vec(";admin=true;");

        let encrypted = wrapper(&input);
        assert_eq!(false, check_admin(encrypted));

        let new_enc = bitflip_attack();
        println!("{:?}", check_admin(new_enc));
    }
}
