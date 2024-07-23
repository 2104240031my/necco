#[allow(unused)]

use crate::crypto::CryptoError;
use crate::crypto::aes::Aes;

pub trait BlockCipher {
    const BLOCK_SIZE: usize;
    unsafe fn encrypt_unchecked(&self, block_in: *const u8, block_out: *mut u8);
    unsafe fn decrypt_unchecked(&self, block_in: *const u8, block_out: *mut u8);
    fn encrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
    fn decrypt(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
}

pub struct BlockCipherOperation {}
impl BlockCipherOperation {

    pub fn ecb_encrypt(cipher: &impl BlockCipher, bytes_in: &[u8], bytes_out: &mut [u8]) -> Option<CryptoError> {

        let len: usize = bytes_in.len();

        if len > bytes_out.len() {
            return Some(CryptoError::new(""))
        }
        
        if len % <Aes as BlockCipher>::BLOCK_SIZE != 0 {
            return Some(CryptoError::new(""));
        }

        let mut i: usize = 0;

        while i < len {
            unsafe {
                cipher.encrypt_unchecked(
                    bytes_in[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)].as_ptr() as *const u8,
                    bytes_out[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)].as_ptr() as *mut u8
                );
            }
            i = i + <Aes as BlockCipher>::BLOCK_SIZE;
        }

        return None;

    }

    pub fn ecb_decrypt(cipher: &impl BlockCipher, bytes_in: &[u8], bytes_out: &mut [u8]) -> Option<CryptoError> {

        let len: usize = bytes_in.len();

        if len > bytes_out.len() {
            return Some(CryptoError::new(""))
        }
        
        if len % <Aes as BlockCipher>::BLOCK_SIZE != 0 {
            return Some(CryptoError::new(""));
        }

        let mut i: usize = 0;

        while i < len {
            unsafe {
                cipher.decrypt_unchecked(
                    bytes_in[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)].as_ptr() as *const u8,
                    bytes_out[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)].as_ptr() as *mut u8
                );
            }
            i = i + <Aes as BlockCipher>::BLOCK_SIZE;
        }

        return None;

    }

    pub fn ctr(ciph: &impl BlockCipher, ctr_blk: &mut [u8], ctr_size: usize, bytes_in: &[u8], 
        bytes_out: &mut [u8]) -> Option<CryptoError> {

        if bytes_in.len() > bytes_out.len() {
            return Some(CryptoError::new(""));
        }

        if ctr_blk.len() < <Aes as BlockCipher>::BLOCK_SIZE {
            return Some(CryptoError::new(""));
        }

        let mut c: [u8; <Aes as BlockCipher>::BLOCK_SIZE] = [0x00; <Aes as BlockCipher>::BLOCK_SIZE];
        let mut i: usize = 0;
        let n: usize = (bytes_in.len() % <Aes as BlockCipher>::BLOCK_SIZE) * <Aes as BlockCipher>::BLOCK_SIZE;

        while i < n {
            ciph.encrypt(&ctr_blk[..], &mut c[..])?;
            unsafe { 
                Self::xor_block(
                    (&bytes_in[i..] ).as_ptr() as *const u8, 
                    (&c[..]       ).as_ptr() as *const u8,
                    (&bytes_out[i..]).as_ptr() as *mut u8,
                    <Aes as BlockCipher>::BLOCK_SIZE
                )
            };
            Self::inc_counter_block_by_one(ctr_blk, ctr_size, <Aes as BlockCipher>::BLOCK_SIZE);
            i = i + <Aes as BlockCipher>::BLOCK_SIZE;
        }
        
        if i != n {
            ciph.encrypt(&ctr_blk[..], &mut c[..])?;
            for j in 0..(n - bytes_in.len()) {
                bytes_out[i + j] = bytes_in[i + j] ^ c[j];
            }
            Self::inc_counter_block_by_one(ctr_blk, ctr_size, <Aes as BlockCipher>::BLOCK_SIZE);
        }

        return None;

    }

    fn inc_counter_block_by_one(ctr_blk: &mut [u8], ctr_size: usize, blk_size: usize) {
        
        let mut a = 1;
        let mut j = blk_size - 1;
        
        while j > ctr_size {
            a = a + (ctr_blk[j] as usize);
            ctr_blk[j] = (a & 0xff) as u8;
            a = a >> 8;
            j = j - 1;
        }

    }
    
    unsafe fn xor_block(src1: *const u8, src2: *const u8, dst: *mut u8, len: usize) {

        let mut i: usize = 0;
        let n: usize     = len >> 3;

        while i < n {
            *(dst as *mut u64).add(i) = *(src1 as *const u64).add(i) ^ *(src2 as *const u64).add(i);
            i = i + 1;
        }

        i = i << 3;

        while i < len {
            *dst.add(i) = *src1.add(i) ^ *src2.add(i);
            i = i + 1;
        }

    }
    
}
