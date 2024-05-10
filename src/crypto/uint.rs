#[warn(non_camel_case_types)]
pub struct u256 {
    w: [u32; 8]
}

impl u256 {

    pub fn zero() -> Self {
        return u256{ w: [0; 8] };
    }

    pub fn from_be_bytes(&mut self, b: [u8; 32]) {
        for i in 0..8 {
            let j: usize = i << 2;
            self.w[i] = (
                ((b[j + 0]  as u32) << 24) | 
                ((b[j + 1]  as u32) << 16) | 
                ((b[j + 2]  as u32) <<  8) | 
                ((b[j + 3]  as u32) <<  0)
            );
        }
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

    pub fn add(assign_to: &mut Self, lhs: &Self, rhs: &Self) {

        let mut acc: u64 = 0;
        let mut u: usize = 8;
        loop {
            u = u - 1;
            acc = acc + (lhs.w[u] as u64) + (rhs.w[u] as u64);
            assign_to.w[u] = (acc & 0xffffffffu64) as u32;
            acc = acc >> 32;
            if u == 0 {
                break;
            }
        }

    }

    pub fn mul(assign_to: &mut Self, lhs: &Self, rhs: &Self) {

        let mut buf: [u32; 16] = [0; 16];

        for i in 0..8 {
            for j in 0..8 {
                
                let tmp: u64     = (lhs.w[i] as u64) * (rhs.w[j] as u64);
                let mut u: usize = i + j + 1;
                let mut v: usize = u + 1;

                let mut acc: u64 = tmp & 0xffffffffu64;
                loop {
                    v = v - 1;
                    acc = acc + (buf[v] as u64);
                    buf[v] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    if v == 0 {
                        break;
                    }
                }
                
                acc = tmp >> 32;
                loop {
                    u = u - 1;
                    acc = acc + (buf[u] as u64);
                    buf[u] = (acc & 0xffffffffu64) as u32;
                    acc = acc >> 32;
                    if u == 0 {
                        break;
                    }
                }
    
            }
        }
    
        for i in 0..8 {
            assign_to.w[i] = buf[i + 8];
        }
    
    }
    
    pub fn eq(lhs: &Self, rhs: &Self) -> bool {
        
        let mut acc: u64 = 0;
        
        for i in 0..8 {
            acc = acc | ((lhs.w[i] as u64) ^ (rhs.w[i] as u64));
        }
        
        return acc == 0;
    
    }

}
