use std::ptr;
use crate::crypto::CryptoError;
use crate::crypto::aes::Aes;

pub trait BlockCipher {
    const BLOCK_SIZE: usize;
    fn encrypt_block(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
    fn decrypt_block(&self, block_in: &[u8], block_out: &mut [u8]) -> Option<CryptoError>;
}

pub struct BlockCipherOperation {}
impl BlockCipherOperation {

    pub fn ecb_encrypt(ciph: &impl BlockCipher, msg_in: &[u8], msg_out: &mut [u8]) -> Option<CryptoError> {

        if msg_in.len() > msg_out.len() {
            return Some(CryptoError::new("".to_string()))
        }
        
        if msg_in.len() % <Aes as BlockCipher>::BLOCK_SIZE != 0 {
            return Some(CryptoError::new("".to_string()));
        }

        let mut i: usize = 0;

        while i < msg_in.len() {
            ciph.encrypt_block(&msg_in[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)], &mut msg_out[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)])?;
            i = i + <Aes as BlockCipher>::BLOCK_SIZE;
        }

        return None;

    }

    pub fn ecb_decrypt(ciph: &impl BlockCipher, msg_in: &[u8], msg_out: &mut [u8]) -> Option<CryptoError> {

        if msg_in.len() > msg_out.len() {
            return Some(CryptoError::new("".to_string()))
        }
        
        if msg_in.len() % <Aes as BlockCipher>::BLOCK_SIZE != 0 {
            return Some(CryptoError::new("".to_string()));
        }

        let mut i: usize = 0;

        while i < msg_in.len() {
            ciph.decrypt_block(&msg_in[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)], &mut msg_out[i..(i + <Aes as BlockCipher>::BLOCK_SIZE)])?;
            i = i + <Aes as BlockCipher>::BLOCK_SIZE;
        }

        return None;

    }

    pub fn ctr(ciph: &impl BlockCipher, ctr_blk: &mut [u8], ctr_size: usize, msg_in: &[u8], msg_out: &mut [u8]) -> Option<CryptoError> {

        if msg_in.len() > msg_out.len() {
            return Some(CryptoError::new("".to_string()));
        }

        if ctr_blk.len() < <Aes as BlockCipher>::BLOCK_SIZE {
            return Some(CryptoError::new("".to_string()));
        }

        let mut c: [u8; <Aes as BlockCipher>::BLOCK_SIZE] = [0x00; <Aes as BlockCipher>::BLOCK_SIZE];
        let mut i: usize = 0;
        let n: usize = (msg_in.len() % <Aes as BlockCipher>::BLOCK_SIZE) * <Aes as BlockCipher>::BLOCK_SIZE;

        while i < n {
            ciph.encrypt_block(&ctr_blk[..], &mut c[..])?;
            unsafe { 
                Self::xor_block(
                    (&msg_in[i..] ).as_ptr() as *const u8, 
                    (&c[..]       ).as_ptr() as *const u8,
                    (&msg_out[i..]).as_ptr() as *mut u8,
                    <Aes as BlockCipher>::BLOCK_SIZE
                )
            };
            Self::inc_counter_block_by_one(ctr_blk, ctr_size, <Aes as BlockCipher>::BLOCK_SIZE);
            i = i + <Aes as BlockCipher>::BLOCK_SIZE;
        }
        
        if i != n {
            ciph.encrypt_block(&ctr_blk[..], &mut c[..])?;
            for j in 0..(n - msg_in.len()) {
                msg_out[i + j] = msg_in[i + j] ^ c[j];
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
