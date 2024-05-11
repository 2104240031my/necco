use crate::crypto::CryptoError;
use crate::crypto::uint::Uint256;

pub struct Uint25519 {
    u256: Uint256
}

impl Uint25519 {

    // (2 ^ 255) - 19 == 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    const MODULE: Uint256 = Uint256{ w: [
        0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed
    ]};
    
    // (2 ^ 256) - MODULE == 0x8000000000000000000000000000000000000000000000000000000000000013
    const MODULE_ADDINV256: Uint256 = Uint256{ w: [
        0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000013
    ]};

    // (486662 - 2) / 4 == 121665 == 0x000000000000000000000000000000000000000000000000000000000001db41
    const A24: Uint256 = Uint256{ w: [
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0001db41
    ]};

    // ((2 ^ 255) - 19) - 2
    // 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    const MODULE_SUB_2: Uint256 = Uint256{ w: [
        0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffeb
    ]};

    pub fn new() -> Self {
        return Uint25519{ u256: Uint256{ w: [0; 8] }};
    }

    pub fn new_as(u: usize) -> Self {
        return Uint25519{ u256: Uint256::new_as(u) };
    }

    pub fn new_with_be_bytes(b: [u8; 32]) -> Result<Self, CryptoError> {
        if !Self::convertable_bytes(&b[..]) {
            return Err(CryptoError::new("the bytes \"b\" could not convert into Uint25519 value".to_string()));
        }
        return Ok(Uint25519{ u256: Uint256::new_with_be_bytes(b) });
    }

    pub fn with_be_bytes(&mut self, b: [u8; 32]) -> Result<Self, CryptoError> {
        if let Some(e) = self.from_be_bytes(b) {
            return Err(e);
        }
        return Ok(Uint25519{ u256: Uint256{ w: self.u256.w }});
    }

    pub fn from_be_bytes(&mut self, b: [u8; 32]) -> Option<CryptoError> {
        if !Self::convertable_bytes(&b[..]) {
            return Some(CryptoError::new("the bytes \"b\" could not convert into Uint25519 value".to_string()));
        }
        self.u256.from_be_bytes(b);
        return None;
    }

    pub fn try_from_be_bytes(&mut self, b: &[u8]) -> Option<CryptoError> {
        return self.u256.try_from_be_bytes(b);
    }

    pub fn to_be_bytes(&self, assign_to: &mut [u8; 32]) { 
        self.u256.to_be_bytes(assign_to);
    }

    pub fn gadd(into: &mut Self, lhs: &Uint25519, rhs: &Uint25519) {
        Uint256::add(&mut into.u256, &lhs.u256, &rhs.u256);
        into.may_sub_module_once();
    }

    pub fn gsub(into: &mut Self, lhs: &Uint25519, rhs: &Uint25519) {
        let mut rhs_addinv256: Uint256 = Uint256::new();
        Self::addinv256(&mut rhs_addinv256, &rhs.u256);
        Uint256::add(&mut into.u256, &lhs.u256, &rhs_addinv256);
        into.may_sub_module_once();
    }

    pub fn gmul(into: &mut Self, lhs: &Uint25519, rhs: &Uint25519) {

        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;
        let mut k: usize;
                
        for i in 0..8 {
            for j in 0..8 {
                
                let tmp: u64 = (lhs.u256.w[i] as u64) * (rhs.u256.w[j] as u64);
                
                acc = tmp & 0xffffffffu64;
                k = i + j + 2;
                loop {
                    k = k - 1;
                    acc = acc + (buf[k] as u64);
                    buf[k] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    if k == 0 {
                        break;
                    }
                }
                
                acc = tmp >> 32;
                k = i + j + 1;
                loop {
                    k = k - 1;
                    acc = acc + (buf[k] as u64);
                    buf[k] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    if k == 0 {
                        break;
                    }
                }
    
            }
        }

        acc    = ((!(((buf[8] >> 31) & 1u32).wrapping_sub(1))) & 19) as u64;
        buf[8] = buf[8] & 0x7fffffffu32;
        k      = 8;
        loop {
            k = k - 1;
            let tmp: u64 = buf[k] as u64;
            acc = acc + (buf[k + 8] as u64) + (tmp << 5) + (tmp << 2) + (tmp << 1);
            buf[k + 8] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if k == 0 {
                break;
            }
        }

        acc    = (acc << 5) + (acc << 2) + (acc << 1);
        acc    = acc + (((!(((buf[8] >> 31) & 1u32).wrapping_sub(1))) & 19) as u64);
        buf[8] = buf[8] & 0x7fffffffu32;
        k      = 8;
        loop {
            k = k - 1;
            acc = acc + (buf[k + 8] as u64);
            into.u256.w[k] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if k == 0 {
                break;
            }
        }

        into.may_sub_module_once();

    }

    fn addinv256(into: &mut Uint256, from: &Uint256) {
        let mut acc: u64 = 1;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + ((!(from.w[u] as u64)) & 0xffffffffu64) + (Self::MODULE.w[u] as u64);
            into.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }
    }

    fn may_sub_module_once(&mut self) {
        let mask: u32    = if !self.has_valid_value() { u32::MAX } else { 0u32 };
        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (self.u256.w[u] as u64) + ((Self::MODULE_ADDINV256.w[u] & mask) as u64);
            self.u256.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }
    }

    fn convertable_bytes(b: &[u8]) -> bool {
        return (b[0] < 0x7f) || ((b[0] < 0x80) && b[31] < 0xed);
    }

    fn has_valid_value(&mut self) -> bool {
        return Uint256::lt(&self.u256, &Self::MODULE);
    }

}
