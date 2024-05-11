mod crypto;
use crypto::aes;
use crypto::sha3;
use crypto::uint::Uint256;
use crypto::curve25519::Uint25519;

fn main() {

    let k = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let p = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
    let c = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
    let out = [0x00u8; 16];
    let aes = aes::Aes::new(aes::AesAlgorithm::Aes128, &k[..]).unwrap();
    
    aes.cipher(&p[..], &out[..]);
    printlnbytes(&out[..]);
    
    aes.inv_cipher(&c[..], &out[..]);
    printlnbytes(&out[..]);


    let msg: [u8; 0] = [0u8; 0];
    let mut md: [u8; 64] = [0u8; 64];
    
    sha3::Sha3::compute(sha3::Sha3Algorithm::Sha3_224, &msg[..], &mut md[..]);
    printlnbytes(&md[..28]);
    
    sha3::Sha3::compute(sha3::Sha3Algorithm::Sha3_256, &msg[..], &mut md[..]);
    printlnbytes(&md[..32]);
    
    sha3::Sha3::compute(sha3::Sha3Algorithm::Sha3_384, &msg[..], &mut md[..]);
    printlnbytes(&md[..48]);
    
    sha3::Sha3::compute(sha3::Sha3Algorithm::Sha3_512, &msg[..], &mut md[..]);
    printlnbytes(&md[..64]);

    let a: Uint25519 = Uint25519::new().with_be_bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
    ]).unwrap();

    let b: Uint25519 = Uint25519::new().with_be_bytes([
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00
    ]).unwrap();
    
    let mut c: Uint25519 = Uint25519::new_as(0);
    let mut d: Uint25519 = Uint25519::new_as(0);
    let mut e: Uint25519 = Uint25519::new_as(0);

    Uint25519::gadd(&mut c, &a, &b);
    Uint25519::gsub(&mut d, &a, &b);
    Uint25519::gmul(&mut e, &a, &b);

    let mut out: [u8; 32] = [0; 32];
    
    a.to_be_bytes(&mut out);
    printlnbytes(&out);
    b.to_be_bytes(&mut out);
    printlnbytes(&out);

    c.to_be_bytes(&mut out);
    printlnbytes(&out);

    d.to_be_bytes(&mut out);
    printlnbytes(&out);
    
    e.to_be_bytes(&mut out);
    printlnbytes(&out);

}

fn printlnbytes(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
    println!();
}