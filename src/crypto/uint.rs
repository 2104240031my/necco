use crate::crypto::CryptoError;

pub struct Uint256 {
    pub w: [u32; 8]
}

impl Uint256 {

    pub fn new() -> Self {
        return Uint256{ w: [0; 8] };
    }
    
    pub fn new_as(u: usize) -> Self {
        return Uint256{ w: [ 0, 0, 0, 0, 0, 0, (u >> 32) as u32, (u & 0xffffffffusize) as u32 ]};
    }

    pub fn new_with_be_bytes(b: [u8; 32]) -> Self {
        return Uint256{ w: [
            ((b[0]  as u32) << 24) | ((b[1]  as u32) << 16) | ((b[2]  as u32) << 8) | ((b[3]  as u32) << 0),
            ((b[4]  as u32) << 24) | ((b[5]  as u32) << 16) | ((b[6]  as u32) << 8) | ((b[7]  as u32) << 0),
            ((b[8]  as u32) << 24) | ((b[9]  as u32) << 16) | ((b[10] as u32) << 8) | ((b[11] as u32) << 0),
            ((b[12] as u32) << 24) | ((b[13] as u32) << 16) | ((b[14] as u32) << 8) | ((b[15] as u32) << 0),
            ((b[16] as u32) << 24) | ((b[17] as u32) << 16) | ((b[18] as u32) << 8) | ((b[19] as u32) << 0),
            ((b[20] as u32) << 24) | ((b[21] as u32) << 16) | ((b[22] as u32) << 8) | ((b[23] as u32) << 0),
            ((b[24] as u32) << 24) | ((b[25] as u32) << 16) | ((b[26] as u32) << 8) | ((b[27] as u32) << 0),
            ((b[28] as u32) << 24) | ((b[29] as u32) << 16) | ((b[30] as u32) << 8) | ((b[31] as u32) << 0)
        ]};
    }

    pub fn with_be_bytes(&mut self, b: [u8; 32]) -> Self {
        self.from_be_bytes(b);
        return Uint256{ w: self.w };
    }

    pub fn from_be_bytes(&mut self, b: [u8; 32]) {
        for i in 0..8 {
            let j: usize = i << 2;
            self.w[i] = (
                ((b[j + 0] as u32) << 24) | 
                ((b[j + 1] as u32) << 16) | 
                ((b[j + 2] as u32) <<  8) | 
                ((b[j + 3] as u32) <<  0)
            );
        }
    }

    pub fn try_from_be_bytes(&mut self, b: &[u8]) -> Option<CryptoError> {
        
        if b.len() < 32 {
            return Some(CryptoError::new("the length of bytes \"b\" is not enough".to_string()));
        }

        for i in 0..8 {
            let j: usize = i << 2;
            self.w[i] = (
                ((b[j + 0] as u32) << 24) | 
                ((b[j + 1] as u32) << 16) | 
                ((b[j + 2] as u32) <<  8) | 
                ((b[j + 3] as u32) <<  0)
            );
        }

        return None;

    }

    pub fn to_be_bytes(&self, assign_to: &mut [u8; 32]) {
        for i in 0..8 {
            let j: usize = i << 2;
            assign_to[j + 0] = (self.w[i] >> 24) as u8;
            assign_to[j + 1] = (self.w[i] >> 16) as u8;
            assign_to[j + 2] = (self.w[i] >>  8) as u8;
            assign_to[j + 3] = (self.w[i] >>  0) as u8;
        }
    }

    pub fn add(into: &mut Self, lhs: &Self, rhs: &Self) {

        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (lhs.w[u] as u64) + (rhs.w[u] as u64);
            into.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }

    }

    pub fn add_into(&mut self, lhs: &Self, rhs: &Self) -> &Self {
        Self::add(self, lhs, rhs);
        return self;
    }

    pub fn add_into_self(&mut self, rhs: &Self) -> &Self {

        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (self.w[u] as u64) + (rhs.w[u] as u64);
            self.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }

        return self;

    }

    pub fn mul(into: &mut Self, lhs: &Self, rhs: &Self) {

        for i in 0..8 {
            for j in 0..8 {
                
                let tmp: u64 = (lhs.w[i] as u64) * (rhs.w[j] as u64);
                let mut acc: u64;
                let mut k: usize;
                
                acc = tmp & 0xffffffffu64;
                k = i + j + 1;
                while k > 8 {
                    acc = acc + (into.w[k - 8] as u64);
                    into.w[k - 8] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    k = k - 1;
                }
                
                acc = tmp >> 32;
                k = i + j;
                while k > 8 {
                    acc = acc + (into.w[k - 8] as u64);
                    into.w[k - 8] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    k = k - 1;
                }
    
            }
        }
    
    }

    pub fn mul_into(&mut self, lhs: &Self, rhs: &Self) -> &Self {
        Self::mul(self, lhs, rhs);
        return self;
    }

    pub fn eq(lhs: &Self, rhs: &Self) -> bool {
        
        let mut acc: u64 = 0;
        
        for i in 0..8 {
            acc = acc | ((lhs.w[i] as u64) ^ (rhs.w[i] as u64));
        }
        
        return acc == 0;
    
    }
    
    pub fn lt(lhs: &Self, rhs: &Self) -> bool {

        let mut bit: u64 = 1; // current bit
        let mut l: u64   = 0; // summary of left
        let mut r: u64   = 0; // summary of right
        let mut i: usize = 8;

        while i > 0 {
            i = i - 1;
            let gt_mask: u64 = if lhs.w[i] > rhs.w[i] { u64::MAX } else { 0u64 };
            let lt_mask: u64 = if lhs.w[i] < rhs.w[i] { u64::MAX } else { 0u64 };
            l = l ^ (bit & gt_mask);
            r = r ^ (bit & lt_mask);
            bit = bit << 1;
        }

        return l < r;

    }

}
