use crate::crypto::CryptoError;

pub enum Sha3Algorithm {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512
}

pub struct Sha3 {
    a: [[u64; 5]; 5], // Keccak1600 state
    d: usize,         // message digest size (in bytes)
    r: usize,         // rate (in bytes)
    w: usize,         // lane size of Keccak-p permutation (in bytes), i.e., r / 8
}

const SHA3_NR: usize = 24;

static RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

static ROT: [[usize; 5]; 5] = [
    [ 0, 36,  3, 41, 18], //  0,  1, 62, 28, 27,
    [ 1, 44, 10, 45 , 2], // 36, 44,  6, 55, 20,
    [62,  6, 43, 15, 61], //  3, 10, 43, 25, 39,
    [28, 55, 25, 21, 56], // 41, 45, 15, 21,  8,
    [27, 20, 39,  8, 14]  // 18,  2, 61, 56, 14
];

fn rotl64(u: u64, r: usize) -> u64 {
    return (u << r) | (u >> ((64 - r) & 63));
}

impl Sha3 {

    fn new(algo: Sha3Algorithm) -> Result<Self, CryptoError> {
        return Ok(match algo {
            Sha3Algorithm::Sha3_224 => Sha3{ a: [[0u64; 5]; 5], d: 28, r: 144, w: 18 },
            Sha3Algorithm::Sha3_256 => Sha3{ a: [[0u64; 5]; 5], d: 32, r: 136, w: 17 },
            Sha3Algorithm::Sha3_384 => Sha3{ a: [[0u64; 5]; 5], d: 48, r: 104, w: 13 },
            Sha3Algorithm::Sha3_512 => Sha3{ a: [[0u64; 5]; 5], d: 64, r: 72,  w: 9  }
        });
    }

    pub fn compute(algo: Sha3Algorithm, msg: &[u8], md: &mut [u8]) -> Option<CryptoError> {

        let mut sha3: Sha3 = Self::new(algo).ok()?;
        let mut ofs: usize = 0;
        let mut block: [u64; 25] = [0u64; 25];
    
        while msg.len() - ofs >= sha3.r {
            for i in 0..sha3.w {
                block[i] = (
                    ((msg[ofs + 0] as u64) <<  0) | ((msg[ofs + 1] as u64) <<  8) |
                    ((msg[ofs + 2] as u64) << 16) | ((msg[ofs + 3] as u64) << 24) |
                    ((msg[ofs + 4] as u64) << 31) | ((msg[ofs + 5] as u64) << 40) |
                    ((msg[ofs + 6] as u64) << 48) | ((msg[ofs + 7] as u64) << 56)
                );
                ofs = ofs + 8;
            }
            for y in 0..5 {
                for x in 0..5 {
                    sha3.a[x][y] = sha3.a[x][y] ^ block[x + 5 * y]; // ここ大事な、XORで吸収
                }
            }
            sha3.absorb();
        }
    
        let mut x: usize = 0;
        let mut y: usize = 0;
        let mut n: usize = 0;
    
        while ofs < msg.len() {
            sha3.a[x][y] = sha3.a[x][y] ^ ((msg[ofs] as u64) << n);
            n = n + 8;
            if n == 64 {
                n = 0;
                x = x + 1;
                if x == 5 {
                    y = y + 1;
                }
            }
            ofs = ofs + 1;
        }
    
        sha3.a[x][y] = sha3.a[x][y] ^ (0x06u64 << n);
        x = (sha3.w % 5) - 1;
        y = sha3.w / 5;
        sha3.a[x][y] = sha3.a[x][y] ^ (0x80u64 << 56);
        sha3.absorb();
    
        n = 0;
        x = 0;
        y = 0;
    
        for i in 0..sha3.d {
            md[i] = ((sha3.a[x][y] >> n) & 0xff) as u8;
            n = n + 8;
            if n == 64 {
                n = 0;
                x = x + 1;
                if x == 5 {
                    x = 0;
                    y = y + 1;
                }
            }
        }
    
        return None;
    
    }

    fn reset(&mut self) {
        for y in 0..5 {
            for x in 0..5 {
                self.a[x][y] = 0;
            }
        }
    }

    fn absorb(&mut self) {
        for i in 0..SHA3_NR {
            self.round(i);
        }
    }

    fn round(&mut self, round_idx: usize) {

        let mut b: [[u64; 5]; 5] = [[0u64; 5]; 5];
        let mut c: [u64; 5] = [0u64; 5];
        let mut d: [u64; 5] = [0u64; 5];
    
        c[0] = self.a[0][0] ^ self.a[0][1] ^ self.a[0][2] ^ self.a[0][3] ^ self.a[0][4];
        c[1] = self.a[1][0] ^ self.a[1][1] ^ self.a[1][2] ^ self.a[1][3] ^ self.a[1][4];
        c[2] = self.a[2][0] ^ self.a[2][1] ^ self.a[2][2] ^ self.a[2][3] ^ self.a[2][4];
        c[3] = self.a[3][0] ^ self.a[3][1] ^ self.a[3][2] ^ self.a[3][3] ^ self.a[3][4];
        c[4] = self.a[4][0] ^ self.a[4][1] ^ self.a[4][2] ^ self.a[4][3] ^ self.a[4][4];

        d[0] = c[4] ^ rotl64(c[1], 1);
        d[1] = c[0] ^ rotl64(c[2], 1);
        d[2] = c[1] ^ rotl64(c[3], 1);
        d[3] = c[2] ^ rotl64(c[4], 1);
        d[4] = c[3] ^ rotl64(c[0], 1);
    
        for y in 0..5 {
            self.a[0][y] = self.a[0][y] ^ d[0];
            self.a[1][y] = self.a[1][y] ^ d[1];
            self.a[2][y] = self.a[2][y] ^ d[2];
            self.a[3][y] = self.a[3][y] ^ d[3];
            self.a[4][y] = self.a[4][y] ^ d[4];
        }
    
        for x in 0..5 {
            b[0][(2 * x +  0) % 5] = rotl64(self.a[x][0], ROT[x][0]);
            b[1][(2 * x +  3) % 5] = rotl64(self.a[x][1], ROT[x][1]);
            b[2][(2 * x +  6) % 5] = rotl64(self.a[x][2], ROT[x][2]);
            b[3][(2 * x +  9) % 5] = rotl64(self.a[x][3], ROT[x][3]);
            b[4][(2 * x + 12) % 5] = rotl64(self.a[x][4], ROT[x][4]);
        }
    
        for x in 0..5 {
            self.a[x][0] = b[x][0] ^ ((!b[(x + 1) % 5][0]) & b[(x + 2) % 5][0]);
            self.a[x][1] = b[x][1] ^ ((!b[(x + 1) % 5][1]) & b[(x + 2) % 5][1]);
            self.a[x][2] = b[x][2] ^ ((!b[(x + 1) % 5][2]) & b[(x + 2) % 5][2]);
            self.a[x][3] = b[x][3] ^ ((!b[(x + 1) % 5][3]) & b[(x + 2) % 5][3]);
            self.a[x][4] = b[x][4] ^ ((!b[(x + 1) % 5][4]) & b[(x + 2) % 5][4]);
        }

        self.a[0][0] = self.a[0][0] ^ RC[round_idx];
    
    }

}

// bitレベルでリトルエンディアン
// つまり
//         <- 0bit  63bit ->
// ビット列 11110000...0001 (64bit)
// は
// uint64 内で
//
// <- 63bit         0bit ->
// 1000...00001111
// として配置される
//
// ただし、入力バイト列（ネットワークバイトオーダー、各オクテット内のビットはリトルエンディアン）
// である場合は、そもそも各オクテット内でリトルエンディアン（7, 6, 5, 4, 3, 2, 1, 0）
// の順に並んでいるので、バイトレベルのエンディアン変換だけでOK
