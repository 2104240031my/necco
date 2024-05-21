use crate::crypto::CryptoError;
use crate::crypto::uint::Uint256;

pub struct X25519 {
    priv_key: [u8; 32]
}

struct Curve25519Uint {
    u256: Uint256
}

impl X25519 {

    const PRIVATE_KEY_LEN: usize   = 32;
    const PUBLIC_KEY_LEN: usize    = 32;
    const SHARED_SECRET_LEN: usize = 32;

    // (486662 - 2) / 4 == 121665 == 0x000000000000000000000000000000000000000000000000000000000001db41
    const A24: Curve25519Uint = Curve25519Uint{ u256: Uint256{ w: [
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0001db41
    ]}};

    // ((2 ^ 255) - 19) - 2
    // 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    const MODULE_SUB_2: Curve25519Uint = Curve25519Uint{ u256: Uint256{ w: [
        0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffeb
    ]}};

    const U: Curve25519Uint = Curve25519Uint{ u256: Uint256{ w: [
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009
    ]}};

    pub fn compute_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Option<CryptoError> {

        if priv_key.len() < X25519::PRIVATE_KEY_LEN {
            return Some(CryptoError::new("the length of \"priv_key\" is not enough".to_string()));
        } else if pub_key.len() < X25519::PUBLIC_KEY_LEN {
            return Some(CryptoError::new("the length of \"pub_key\" is not enough".to_string()));
        }

        let mut k: Curve25519Uint = Curve25519Uint::try_new_with_bytes(priv_key).ok()?;
        k.u256.w[0] = (k.u256.w[0] & 0x7fffffffu32) | 0x40000000u32;
        k.u256.w[7] = k.u256.w[7] & 0xfffffff8u32;
        
        let mut v: Curve25519Uint = Curve25519Uint::new();

        X25519::x25519_core(&mut v, &k, &X25519::U);
        v.try_to_bytes(pub_key)?;

        return None;

    }

    pub fn compute_shared_secret(priv_key: &[u8], peer_pub_key: &[u8], shared_secret: &mut [u8]) -> Option<CryptoError> {

        if priv_key.len() < X25519::PRIVATE_KEY_LEN {
            return Some(CryptoError::new("the length of \"priv_key\" is not enough".to_string()));
        } else if peer_pub_key.len() < X25519::PUBLIC_KEY_LEN {
            return Some(CryptoError::new("the length of \"pub_key\" is not enough".to_string()));
        } else if shared_secret.len() < X25519::SHARED_SECRET_LEN {
            return Some(CryptoError::new("the length of \"shared_secret\" is not enough".to_string()));
        }

        let mut k: Curve25519Uint = Curve25519Uint::try_new_with_bytes(priv_key).ok()?;
        k.u256.w[0] = (k.u256.w[0] & 0x7fffffffu32) | 0x40000000u32;
        k.u256.w[7] = k.u256.w[7] & 0xfffffff8u32;
        
        let mut u: Curve25519Uint = Curve25519Uint::try_new_with_bytes(peer_pub_key).ok()?;
        u.u256.w[0] = u.u256.w[0] & 0x7fffffffu32;
        Curve25519Uint::may_sub_module_once(&mut u);
        
        let mut v: Curve25519Uint = Curve25519Uint::new();
        X25519::x25519_core(&mut v, &k, &u);
        v.try_to_bytes(shared_secret)?;

        return None;

    }

    fn x25519_core(out: &mut Curve25519Uint, k: &Curve25519Uint, u: &Curve25519Uint) {

        let mut x1: Curve25519Uint = u.clone(); 
        let mut x2: Curve25519Uint = Curve25519Uint::new_as(1);
        let mut z2: Curve25519Uint = Curve25519Uint::new_as(0);
        let mut x3: Curve25519Uint = u.clone();
        let mut z3: Curve25519Uint = Curve25519Uint::new_as(1);
        
        let mut t0: Curve25519Uint = Curve25519Uint::new();
        let mut t1: Curve25519Uint = Curve25519Uint::new();
        let mut t2: Curve25519Uint = Curve25519Uint::new();
        let mut t3: Curve25519Uint = Curve25519Uint::new();
        let mut t4: Curve25519Uint = Curve25519Uint::new();
        
        let mut swap: usize = 0;
        let mut bit: usize;

        let mut j: usize = 31; // i == 0 ? j = 31 : 32;
        
        for i in 0..8 {
            
            loop {
                
                j = j - 1;
                
                bit = ((k.u256.w[i] as usize) >> j) & 1;
                swap = swap ^ bit;
                Self::constant_time_swap(swap, &mut x2, &mut x3);
                Self::constant_time_swap(swap, &mut z2, &mut z3);
                swap = bit;

                Curve25519Uint::gadd(&mut t0, &x2, &z2);        // A  = x2 + z2
                Curve25519Uint::gsub(&mut t1, &x2, &z2);        // B  = x2 - z2
                Curve25519Uint::gsqr(&mut t2, &t0);             // AA = A ^ 2
                Curve25519Uint::gsqr(&mut t3, &t1);             // BB = B ^ 2
                Curve25519Uint::gmul(&mut x2, &t2, &t3);        // x2 = AA * BB
                Curve25519Uint::gsub(&mut t4, &t2, &t3);        // E  = AA - BB
                Curve25519Uint::gmul(&mut t3, &Self::A24, &t4);
                Curve25519Uint::gadd_overwrite(&mut t3, &t2);
                Curve25519Uint::gmul(&mut z2, &t4, &t3);        // z2 = E * (AA + a24 * E)
                Curve25519Uint::gsub(&mut t2, &x3, &z3);        // D  = x3 - z3
                Curve25519Uint::gmul_overwrite(&mut t2, &t0);   // DA = D * A
                Curve25519Uint::gadd(&mut t3, &x3, &z3);        // C  = x3 + z3
                Curve25519Uint::gmul_overwrite(&mut t3, &t1);   // CB = C * B
                Curve25519Uint::gadd(&mut t0, &t2, &t3);
                Curve25519Uint::gmul(&mut x3, &t0, &t0);        // x3 = (DA + CB) ^ 2
                Curve25519Uint::gsub(&mut t0, &t2, &t3);
                Curve25519Uint::gsqr_overwrite(&mut t0);
                Curve25519Uint::gmul(&mut z3, &x1, &t0);        // z3 = x1 * (DA - CB) ^ 2

                if j == 0 {
                    break;
                }

            }
            
            j = 32;

        }

        Self::constant_time_swap(swap, &mut x2, &mut x3);
        Self::constant_time_swap(swap, &mut z2, &mut z3);
        
        Curve25519Uint::gpow_overwrite(&mut z2, &Self::MODULE_SUB_2);
        Curve25519Uint::gmul(out, &x2, &z2); // return x2 * (z2 ^ (p - 2))

    }

    fn constant_time_swap(swap: usize, a: &mut Curve25519Uint, b: &mut Curve25519Uint) {
        let mask: u32 = 0u32.wrapping_sub(swap as u32);
        for i in 0..8 {
            let x: u32 = (a.u256.w[i] ^ b.u256.w[i]) & mask;
            a.u256.w[i] = a.u256.w[i] ^ x;
            b.u256.w[i] = b.u256.w[i] ^ x;
        }
    }

}

impl Curve25519Uint {

    // (2 ^ 255) - 19 == 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    const MODULE: Uint256 = Uint256{ w: [
        0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed
    ]};

    // (2 ^ 256) - MODULE == 0x8000000000000000000000000000000000000000000000000000000000000013
    const MODULE_ADDINV256: Uint256 = Uint256{ w: [
        0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000013
    ]};
    
    pub fn new() -> Curve25519Uint {
        return Curve25519Uint{ u256: Uint256{ w: [0; 8] }};
    }

    pub fn new_as(u: usize) -> Curve25519Uint {
        return Curve25519Uint{ u256: Uint256::new_as(u) };
    }

    pub fn try_new_with_bytes(b: &[u8]) -> Result<Curve25519Uint, CryptoError> {
        
        if b.len() < 32 {
            return Err(CryptoError::new("the length of bytes \"b\" is not enough".to_string()));
        }
        
        if false {
            return Err(CryptoError::new("the bytes \"b\" could not convert into Curve25519Uint value".to_string()));
        }

        return Ok(Curve25519Uint{ u256: Uint256{ w: [
            (b[28] as u32) | ((b[29] as u32) << 8) | ((b[30] as u32) << 16) | ((b[31] as u32) << 24),
            (b[24] as u32) | ((b[25] as u32) << 8) | ((b[26] as u32) << 16) | ((b[27] as u32) << 24),
            (b[20] as u32) | ((b[21] as u32) << 8) | ((b[22] as u32) << 16) | ((b[23] as u32) << 24),
            (b[16] as u32) | ((b[17] as u32) << 8) | ((b[18] as u32) << 16) | ((b[19] as u32) << 24),
            (b[12] as u32) | ((b[13] as u32) << 8) | ((b[14] as u32) << 16) | ((b[15] as u32) << 24),
            (b[8]  as u32) | ((b[9]  as u32) << 8) | ((b[10] as u32) << 16) | ((b[11] as u32) << 24),           
            (b[4]  as u32) | ((b[5]  as u32) << 8) | ((b[6]  as u32) << 16) | ((b[7]  as u32) << 24),
            (b[0]  as u32) | ((b[1]  as u32) << 8) | ((b[2]  as u32) << 16) | ((b[3]  as u32) << 24)
        ]}});
        
    }

    pub fn try_from_bytes(&mut self, b: &[u8]) -> Option<CryptoError> {
        
        if b.len() < 32 {
            return Some(CryptoError::new("the length of bytes \"b\" is not enough".to_string()));
        }

        if false {
            return Some(CryptoError::new("the bytes \"b\" could not convert into Curve25519Uint value".to_string()));
        }

        self.u256 = Uint256{ w: [
            (b[28] as u32) | ((b[29] as u32) << 8) | ((b[30] as u32) << 16) | ((b[31] as u32) << 24),
            (b[24] as u32) | ((b[25] as u32) << 8) | ((b[26] as u32) << 16) | ((b[27] as u32) << 24),
            (b[20] as u32) | ((b[21] as u32) << 8) | ((b[22] as u32) << 16) | ((b[23] as u32) << 24),
            (b[16] as u32) | ((b[17] as u32) << 8) | ((b[18] as u32) << 16) | ((b[19] as u32) << 24),
            (b[12] as u32) | ((b[13] as u32) << 8) | ((b[14] as u32) << 16) | ((b[15] as u32) << 24),
            (b[8]  as u32) | ((b[9]  as u32) << 8) | ((b[10] as u32) << 16) | ((b[11] as u32) << 24),           
            (b[4]  as u32) | ((b[5]  as u32) << 8) | ((b[6]  as u32) << 16) | ((b[7]  as u32) << 24),
            (b[0]  as u32) | ((b[1]  as u32) << 8) | ((b[2]  as u32) << 16) | ((b[3]  as u32) << 24)
        ]};

        return None;

    }

    pub fn try_to_bytes(&self, b: &mut [u8]) -> Option<CryptoError> {
        
        if b.len() < 32 {
            return Some(CryptoError::new("the length of bytes \"b\" is not enough".to_string()));
        }

        let mut j = 0;

        for i in 0..8 {
            b[j + 0] = (self.u256.w[7 - i] >>  0) as u8;
            b[j + 1] = (self.u256.w[7 - i] >>  8) as u8;
            b[j + 2] = (self.u256.w[7 - i] >> 16) as u8;
            b[j + 3] = (self.u256.w[7 - i] >> 24) as u8;
            j = j + 4;
        }

        return None;

    }

    pub fn gadd(dst: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gadd_raw(dst as *mut Self, lhs as *const Self, rhs as *const Self);
    }}

    pub fn gsub(dst: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gsub_raw(dst as *mut Self, lhs as *const Self, rhs as *const Self);
    }}
    
    pub fn gmul(dst: &mut Self, lhs: &Self, rhs: &Self) { unsafe {
        Self::gmul_raw(dst as *mut Self, lhs as *const Self, rhs as *const Self);
    }}
    
    pub fn gsqr(dst: &mut Self, src: &Self) { unsafe {
        Self::gmul_raw(dst as *mut Self, src as *const Self, src as *const Self);
    }}

    pub fn gpow(dst: &mut Self, base: &Self, exp: &Self) { unsafe {
        Self::gpow_raw(dst as *mut Self, base as *const Self, exp as *const Self);
    }}

    pub fn gadd_overwrite(lhs_dst: &mut Self, rhs: &Self) { unsafe {
        Self::gadd_raw(lhs_dst as *mut Self, lhs_dst as *const Self, rhs as *const Self);
    }}

    pub fn gsub_overwrite(lhs_dst: &mut Self, rhs: &Self) { unsafe {
        Self::gsub_raw(lhs_dst as *mut Self, lhs_dst as *const Self, rhs as *const Self);
    }}

    pub fn gmul_overwrite(lhs_dst: &mut Self, rhs: &Self) { unsafe {
        Self::gmul_raw(lhs_dst as *mut Self, lhs_dst as *const Self, rhs as *const Self);
    }}

    pub fn gsqr_overwrite(src_dst: &mut Self) { unsafe {
        Self::gmul_raw(src_dst as *mut Self, src_dst as *const Self, src_dst as *const Self);
    }}

    pub fn gpow_overwrite(base_dst: &mut Self, exp: &Self) { unsafe {
        Self::gpow_raw(base_dst as *mut Self, base_dst as *const Self, exp as *const Self);
    }}

    unsafe fn gadd_raw(dst: *mut Self, lhs: *const Self, rhs: *const Self) {
        Uint256::add(&mut (*dst).u256, &(*lhs).u256, &(*rhs).u256);
        Self::may_sub_module_once(&mut (*dst));
    }
    
    unsafe fn gsub_raw(dst: *mut Self, lhs: *const Self, rhs: *const Self) {
        let mut rhs_addinv256: Uint256 = Uint256::new();
        Self::addinv256(&mut rhs_addinv256, &(*rhs).u256);
        Uint256::add(&mut (*dst).u256, &(*lhs).u256, &rhs_addinv256);
        Self::may_sub_module_once(&mut (*dst));
    }

    unsafe fn gmul_raw(dst: *mut Self, lhs: *const Self, rhs: *const Self) {

        let mut buf: [u32; 16] = [0; 16];
        let mut acc: u64;
        let mut k: usize;
                
        for i in 0..8 {
            for j in 0..8 {
                
                let tmp: u64 = ((*lhs).u256.w[i] as u64) * ((*rhs).u256.w[j] as u64);
                
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
            (*dst).u256.w[k] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if k == 0 {
                break;
            }
        }

        Self::may_sub_module_once(&mut (*dst));

    }

    unsafe fn gpow_raw(dst: *mut Self, base: *const Self, exp: *const Self) {

        let mut a: Self = Self::new_as(1);
        let mut b: Self = (*base).clone();

        for i in 0..8 {
            let mut s: u32 = 0x80000000;
            loop {
            
                if ((*exp).u256.w[i] & s) == 0 {
                    Self::gmul_overwrite(&mut b, &a);
                    Self::gsqr_overwrite(&mut a);
                } else {
                    Self::gmul_overwrite(&mut a, &b);
                    Self::gsqr_overwrite(&mut b);
                }
            
                s = s >> 1;

                if s == 0 {
                    break;
                }

            }
        }

        for i in 0..8 {
            (*dst).u256.w[i] = a.u256.w[i];
        }

    }

    pub fn may_sub_module_once(v: &mut Self) {
        let mask: u32    = if Uint256::lt(&v.u256, &Self::MODULE) { 0u32 } else { u32::MAX };
        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (v.u256.w[u] as u64) + ((Self::MODULE_ADDINV256.w[u] & mask) as u64);
            v.u256.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }
    }

    fn addinv256(dst: &mut Uint256, src: &Uint256) {
        let mut acc: u64 = 1;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + ((!(src.w[u] as u64)) & 0xffffffffu64) + (Self::MODULE.w[u] as u64);
            dst.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }
    }

}

impl Clone for Curve25519Uint {

    fn clone(&self) -> Self {
        return Self{ u256: Uint256{ w: [
            self.u256.w[0], self.u256.w[1], self.u256.w[2], self.u256.w[3],
            self.u256.w[4], self.u256.w[5], self.u256.w[6], self.u256.w[7],
        ]}};
    }

}
