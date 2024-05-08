use crate::crypto::CryptoError;

pub enum AesAlgorithm {
    Aes128,
    Aes192,
    Aes256
}

pub struct Aes {
    w:  [u8; 240],
    nk: usize,
    nb: usize,
    nr: usize
}

static S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

static S_BOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

static RCON: [u8; 15] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
];

const AES_128_KEY_LEN: usize = 16;
const AES_192_KEY_LEN: usize = 24;
const AES_256_KEY_LEN: usize = 32;

const AES_128_NK: usize      = 4usize;
const AES_192_NK: usize      = 6usize;
const AES_256_NK: usize      = 8usize;

const AES_128_NB: usize      = 4usize;
const AES_192_NB: usize      = 4usize;
const AES_256_NB: usize      = 4usize;

const AES_128_NR: usize      = 10usize;
const AES_192_NR: usize      = 12usize;
const AES_256_NR: usize      = 14usize;

fn double_on_gf(a: u64) -> u64 {
    let b: u64 = a & 0x8080808080808080;
    return ((a & 0x7f7f7f7f7f7f7f7f) << 1) ^ (b >> 3) ^ (b >> 4) ^ (b >> 6) ^ (b >> 7);
}

impl Aes {

    pub fn new(algo: AesAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            AesAlgorithm::Aes128 => Ok(Self::new_aes_128(key)?),
            AesAlgorithm::Aes192 => Ok(Self::new_aes_192(key)?),
            AesAlgorithm::Aes256 => Ok(Self::new_aes_256(key)?)
        };
    }

    pub fn new_aes_128(key: &[u8]) -> Result<Self, CryptoError> {
        
        if key.len() < AES_128_KEY_LEN {
            return Err(CryptoError::new("key length is too short".to_string()));
        }

        let aes: Aes = Aes{ w : [0x00u8; 240], nk: AES_128_NK, nb: AES_128_NB, nr: AES_128_NR };
        aes.key_expansion(key);
        return Ok(aes);

    }

    pub fn new_aes_192(key: &[u8]) -> Result<Self, CryptoError> {
        
        if key.len() < AES_192_KEY_LEN {
            return Err(CryptoError::new("key length is too short".to_string()));
        }

        let aes: Aes = Aes{ w: [0x00u8; 240], nk: AES_192_NK, nb: AES_192_NB, nr: AES_192_NR };
        aes.key_expansion(key);
        return Ok(aes);

    }

    pub fn new_aes_256(key: &[u8]) -> Result<Self, CryptoError> {

        if key.len() < AES_256_KEY_LEN {
            return Err(CryptoError::new("key length is too short".to_string()));
        }

        let aes: Aes = Aes{ w: [0x00u8; 240], nk: AES_256_NK, nb: AES_256_NB, nr: AES_256_NR };
        aes.key_expansion(key);
        return Ok(aes);

    }

    fn key_expansion(&self, key: &[u8]) { unsafe {

        let k: *const u32 = key.as_ptr() as *const u32;
        let w: *mut u32 = self.w.as_ptr() as *mut u32;
        let mut temp: [u32; 1] = [0u32; 1];
        let t: *mut u8 = temp.as_ptr() as *mut u8;
        
        for i in 0..self.nk {
            *w.add(i) = *k.add(i);
        }
        
        for i in self.nk..(self.nb * (self.nr + 1)) {
     
            temp[0] = *w.add(i - 1);

            if i % self.nk == 0 {

                // RotWord
                let u: u8 = *t.add(0);
                *t.add(0) = *t.add(1);
                *t.add(1) = *t.add(2);
                *t.add(2) = *t.add(3);
                *t.add(3) = u;

                // SubWord
                *t.add(0) = S_BOX[*t.add(0) as usize];
                *t.add(1) = S_BOX[*t.add(1) as usize];
                *t.add(2) = S_BOX[*t.add(2) as usize];
                *t.add(3) = S_BOX[*t.add(3) as usize];

                *t.add(0) = *t.add(0) ^ RCON[i / self.nk];

            } else if self.nk > 6 && i % self.nk == 4 {

                // SubWord
                *t.add(0) = S_BOX[*t.add(0) as usize];
                *t.add(1) = S_BOX[*t.add(1) as usize];
                *t.add(2) = S_BOX[*t.add(2) as usize];
                *t.add(3) = S_BOX[*t.add(3) as usize];

            }

            *w.add(i) = *w.add(i - self.nk) ^ temp[0];

        }

    }}

    pub fn cipher(&self, block_in: &[u8], block_out: &[u8]) -> Option<CryptoError> { unsafe {

        if block_in.len() < 16 {
            return Some(CryptoError::new("the length of $block_in is too short".to_string()));
        } else if block_out.len() < 16 {
            return Some(CryptoError::new("the length of $block_out is too short".to_string()));
        }

        let mut state: [u8; 16] = [0x00u8; 16];
        let s: *mut u64 = state.as_ptr() as *mut u64;
        let mut rk: *mut u64 = self.w.as_ptr() as *mut u64;
        let mut temp: u8;
        let mut t: [u64; 3] = [0u64; 3];
        let t1: *const u8 = (t.as_ptr() as *const u8).add(0);
        let t2: *const u8 = (t.as_ptr() as *const u8).add(8);
        let t3: *const u8 = (t.as_ptr() as *const u8).add(16);
        
        // AddRoundKey
        *s.add(0) = *((block_in.as_ptr() as *const u64).add(0)) ^ *rk.add(0);
        *s.add(1) = *((block_in.as_ptr() as *const u64).add(1)) ^ *rk.add(1);
        rk = rk.add(2);
        
        let mut r: usize = 0;

        loop {
            
            // SubBytes
            state[0]  = S_BOX[state[0]  as usize];
            state[1]  = S_BOX[state[1]  as usize];
            state[2]  = S_BOX[state[2]  as usize];
            state[3]  = S_BOX[state[3]  as usize];
            state[4]  = S_BOX[state[4]  as usize];
            state[5]  = S_BOX[state[5]  as usize];
            state[6]  = S_BOX[state[6]  as usize];
            state[7]  = S_BOX[state[7]  as usize];
            state[8]  = S_BOX[state[8]  as usize];
            state[9]  = S_BOX[state[9]  as usize];
            state[10] = S_BOX[state[10] as usize];
            state[11] = S_BOX[state[11] as usize];
            state[12] = S_BOX[state[12] as usize];
            state[13] = S_BOX[state[13] as usize];
            state[14] = S_BOX[state[14] as usize];
            state[15] = S_BOX[state[15] as usize];

            // ShiftRows
            temp      = state[1];
            state[1]  = state[5];
            state[5]  = state[9];
            state[9]  = state[13];
            state[13] = temp;
            temp      = state[2];
            state[2]  = state[10];
            state[10] = temp;
            temp      = state[6];
            state[6]  = state[14];
            state[14] = temp;
            temp      = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7]  = state[3];
            state[3]  = temp;
            
            r = r + 1;

            if r >= self.nr {
                break;
            }

            // MixColumns
            t[0] = *s.add(0);
            t[1] = double_on_gf(t[0]);
            t[2] = t[0] ^ t[1];
    
            state[0]  = *t2.add(0) ^ *t3.add(1) ^ *t1.add(2) ^ *t1.add(3);
            state[1]  = *t1.add(0) ^ *t2.add(1) ^ *t3.add(2) ^ *t1.add(3);
            state[2]  = *t1.add(0) ^ *t1.add(1) ^ *t2.add(2) ^ *t3.add(3);
            state[3]  = *t3.add(0) ^ *t1.add(1) ^ *t1.add(2) ^ *t2.add(3);
    
            state[4]  = *t2.add(4) ^ *t3.add(5) ^ *t1.add(6) ^ *t1.add(7);
            state[5]  = *t1.add(4) ^ *t2.add(5) ^ *t3.add(6) ^ *t1.add(7);
            state[6]  = *t1.add(4) ^ *t1.add(5) ^ *t2.add(6) ^ *t3.add(7);
            state[7]  = *t3.add(4) ^ *t1.add(5) ^ *t1.add(6) ^ *t2.add(7);
    
            t[0] = *s.add(1);
            t[1] = double_on_gf(t[0]);
            t[2] = t[0] ^ t[1];
            
            state[8]  = *t2.add(0) ^ *t3.add(1) ^ *t1.add(2) ^ *t1.add(3);
            state[9]  = *t1.add(0) ^ *t2.add(1) ^ *t3.add(2) ^ *t1.add(3);
            state[10] = *t1.add(0) ^ *t1.add(1) ^ *t2.add(2) ^ *t3.add(3);
            state[11] = *t3.add(0) ^ *t1.add(1) ^ *t1.add(2) ^ *t2.add(3);
    
            state[12] = *t2.add(4) ^ *t3.add(5) ^ *t1.add(6) ^ *t1.add(7);
            state[13] = *t1.add(4) ^ *t2.add(5) ^ *t3.add(6) ^ *t1.add(7);
            state[14] = *t1.add(4) ^ *t1.add(5) ^ *t2.add(6) ^ *t3.add(7);
            state[15] = *t3.add(4) ^ *t1.add(5) ^ *t1.add(6) ^ *t2.add(7);

            // AddRoundKey
            *s.add(0) = *s.add(0) ^ *rk.add(0);
            *s.add(1) = *s.add(1) ^ *rk.add(1);
            rk = rk.add(2);

        }
        
        // AddRoundKey
        *((block_out.as_ptr() as *mut u64).add(0)) = *s.add(0) ^ *rk.add(0);
        *((block_out.as_ptr() as *mut u64).add(1)) = *s.add(1) ^ *rk.add(1);

        return None;

    }}

    pub fn inv_cipher(&self, block_in: &[u8], block_out: &[u8]) -> Option<CryptoError> { unsafe {

        if block_in.len() < 16 {
            return Some(CryptoError::new("the length of $block_in is too short".to_string()));
        } else if block_out.len() < 16 {
            return Some(CryptoError::new("the length of $block_out is too short".to_string()));
        }

        let mut state: [u8; 16] = [0x00u8; 16];
        let s: *mut u64 = state.as_ptr() as *mut u64;
        let mut rk: *mut u64 = (self.w.as_ptr() as *mut u64).add(self.nr << 1);
        let mut temp: u8;
        let mut t: [u64; 4] = [0u64; 4];
        let t9: *const u8 = (t.as_ptr() as *const u8).add(0);
        let tb: *const u8 = (t.as_ptr() as *const u8).add(8);
        let td: *const u8 = (t.as_ptr() as *const u8).add(16);
        let te: *const u8 = (t.as_ptr() as *const u8).add(24);
        
        // AddRoundKey
        *s.add(0) = *((block_in.as_ptr() as *const u64).add(0)) ^ *rk.add(0);
        *s.add(1) = *((block_in.as_ptr() as *const u64).add(1)) ^ *rk.add(1);
        rk = rk.sub(2);
        
        let mut r: usize = 0;

        loop {
            
            // InvShiftRows
            temp      = state[1];
            state[1]  = state[13];
            state[13] = state[9];
            state[9]  = state[5];
            state[5]  = temp;
            temp      = state[2];
            state[2]  = state[10];
            state[10] = temp;
            temp      = state[6];
            state[6]  = state[14];
            state[14] = temp;
            temp      = state[3];
            state[3]  = state[7];
            state[7]  = state[11];
            state[11] = state[15];
            state[15] = temp;

            // InvSubBytes
            state[0]  = S_BOX_INV[state[0]  as usize];
            state[1]  = S_BOX_INV[state[1]  as usize];
            state[2]  = S_BOX_INV[state[2]  as usize];
            state[3]  = S_BOX_INV[state[3]  as usize];
            state[4]  = S_BOX_INV[state[4]  as usize];
            state[5]  = S_BOX_INV[state[5]  as usize];
            state[6]  = S_BOX_INV[state[6]  as usize];
            state[7]  = S_BOX_INV[state[7]  as usize];
            state[8]  = S_BOX_INV[state[8]  as usize];
            state[9]  = S_BOX_INV[state[9]  as usize];
            state[10] = S_BOX_INV[state[10] as usize];
            state[11] = S_BOX_INV[state[11] as usize];
            state[12] = S_BOX_INV[state[12] as usize];
            state[13] = S_BOX_INV[state[13] as usize];
            state[14] = S_BOX_INV[state[14] as usize];
            state[15] = S_BOX_INV[state[15] as usize];
            
            r = r + 1;

            if r >= self.nr {
                break;
            }
            
            // AddRoundKey
            *s.add(0) = *s.add(0) ^ *rk.add(0);
            *s.add(1) = *s.add(1) ^ *rk.add(1);
            rk = rk.sub(2);
            
            // InvMixColumns
            t[0] = *s.add(0);
            t[1] = double_on_gf(t[0]);
            t[2] = double_on_gf(t[1]);
            t[3] = double_on_gf(t[2]);
            t[0] = t[3] ^ t[0];        // 9
            t[3] = t[3] ^ t[2] ^ t[1]; // e
            t[1] = t[1] ^ t[0];        // b
            t[2] = t[2] ^ t[0];        // d
            
            state[0]  = *te.add(0) ^ *tb.add(1) ^ *td.add(2) ^ *t9.add(3);
            state[1]  = *t9.add(0) ^ *te.add(1) ^ *tb.add(2) ^ *td.add(3);
            state[2]  = *td.add(0) ^ *t9.add(1) ^ *te.add(2) ^ *tb.add(3);
            state[3]  = *tb.add(0) ^ *td.add(1) ^ *t9.add(2) ^ *te.add(3);
    
            state[4]  = *te.add(4) ^ *tb.add(5) ^ *td.add(6) ^ *t9.add(7);
            state[5]  = *t9.add(4) ^ *te.add(5) ^ *tb.add(6) ^ *td.add(7);
            state[6]  = *td.add(4) ^ *t9.add(5) ^ *te.add(6) ^ *tb.add(7);
            state[7]  = *tb.add(4) ^ *td.add(5) ^ *t9.add(6) ^ *te.add(7);

            t[0] = *s.add(1);
            t[1] = double_on_gf(t[0]);
            t[2] = double_on_gf(t[1]);
            t[3] = double_on_gf(t[2]);
            t[0] = t[3] ^ t[0];        // 9
            t[3] = t[3] ^ t[2] ^ t[1]; // e
            t[1] = t[1] ^ t[0];        // b
            t[2] = t[2] ^ t[0];        // d
            
            state[8]  = *te.add(0) ^ *tb.add(1) ^ *td.add(2) ^ *t9.add(3);
            state[9]  = *t9.add(0) ^ *te.add(1) ^ *tb.add(2) ^ *td.add(3);
            state[10] = *td.add(0) ^ *t9.add(1) ^ *te.add(2) ^ *tb.add(3);
            state[11] = *tb.add(0) ^ *td.add(1) ^ *t9.add(2) ^ *te.add(3);
    
            state[12] = *te.add(4) ^ *tb.add(5) ^ *td.add(6) ^ *t9.add(7);
            state[13] = *t9.add(4) ^ *te.add(5) ^ *tb.add(6) ^ *td.add(7);
            state[14] = *td.add(4) ^ *t9.add(5) ^ *te.add(6) ^ *tb.add(7);
            state[15] = *tb.add(4) ^ *td.add(5) ^ *t9.add(6) ^ *te.add(7);
            
        }
        
        // AddRoundKey
        *((block_out.as_ptr() as *mut u64).add(0)) = *s.add(0) ^ *rk.add(0);
        *((block_out.as_ptr() as *mut u64).add(1)) = *s.add(1) ^ *rk.add(1);

        return None;

    }}

}
