use set1::{fixed_xor, hex_decode, hex_encode, hex_to_base64, str_to_vec, vec_to_str};

pub mod set1;
pub mod set2;

fn main() {
    let base64 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let hex = hex_to_base64(str_to_vec(&base64));
    println!("{:?}", vec_to_str(&hex));

    let s1 = hex_decode(&str_to_vec("1c0111001f010100061a024b53535009181c"));
    let s2 = hex_decode(&str_to_vec("686974207468652062756c6c277320657965"));
    let hex = fixed_xor(&s1, &s2);
    println!("{:?}", vec_to_str(&hex_encode(&hex)));
}
