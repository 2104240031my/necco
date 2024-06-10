use crate::necco::error::NeccoError;

struct Vl64 {
    u: u64
};

impl Vl64 {
    
    const BITS_TO_LEN: [usize; 4] = [1, 2, 4, 8];

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, NeccoError> {
        
        if bytes.len() < 1 {
            return Err(NeccoError::new("the length of $bytes is not enough"));
        }
        
        let len: usize = Self::BITS_TO_LEN[(bytes[0] as usize) >> 6];

        if bytes.len() < len {
            return Err(NeccoError::new("the length of $bytes is not enough"));
        }
        
        return Ok(
            Self{ u: match len {
                8 => {(
                    ((bytes[0] as u64) << 56) |
                    ((bytes[1] as u64) << 48) |
                    ((bytes[2] as u64) << 40) |
                    ((bytes[3] as u64) << 32) |
                    ((bytes[4] as u64) << 24) | 
                    ((bytes[5] as u64) << 16) |
                    ((bytes[6] as u64) <<  8) | 
                    ((bytes[7] as u64))
                ) & 0x3fffffffffffffff },
                4 => {(
                    ((bytes[0] as u64) << 24) | 
                    ((bytes[1] as u64) << 16) |
                    ((bytes[2] as u64) <<  8) | 
                    ((bytes[3] as u64))
                ) & 0x3fffffff },
                2 => {(
                    ((bytes[0] as u64) <<  8) | 
                    ((bytes[1] as u64))
                ) & 0x3fff },
                1 => { 
                    ((bytes[3] as u64)) & 0x3f 
                }
            }}
        );
        
    }

    pub fn try_from_mut_bytes(bytes: &mut [u8]) -> Result<Self, NeccoError> {

        if bytes.len() < 1 {
            return Err(NeccoError::new("the length of $bytes is not enough"));
        }
        
        let len: usize = Self::BITS_TO_LEN[(bytes[0] as usize) >> 6];

        if bytes.len() < len {
            return Err(NeccoError::new("the length of $bytes is not enough"));
        }
        
        return Ok(
            Self{ u: match len {
                8 => {(
                    ((bytes[0] as u64) << 56) |
                    ((bytes[1] as u64) << 48) |
                    ((bytes[2] as u64) << 40) |
                    ((bytes[3] as u64) << 32) |
                    ((bytes[4] as u64) << 24) | 
                    ((bytes[5] as u64) << 16) |
                    ((bytes[6] as u64) <<  8) | 
                    ((bytes[7] as u64))
                ) & 0x3fffffffffffffff },
                4 => {(
                    ((bytes[0] as u64) << 24) | 
                    ((bytes[1] as u64) << 16) |
                    ((bytes[2] as u64) <<  8) | 
                    ((bytes[3] as u64))
                ) & 0x3fffffff },
                2 => {(
                    ((bytes[0] as u64) <<  8) | 
                    ((bytes[1] as u64))
                ) & 0x3fff },
                1 => { 
                    ((bytes[3] as u64)) & 0x3f 
                }
            }}
        );

    }

    pub fn to_bytes(self) -> &[u8] {
        
    }
    
    pub fn to_mut_bytes(self) -> &mut [u8] {

    }

}