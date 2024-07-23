use crate::crypto::CryptoError;
use crate::crypto::hash::Hash;

pub struct Sha224 {
    state: Sha2State32
}

pub struct Sha256 {
    state: Sha2State32
}

pub struct Sha384 {
    state: Sha2State64
}

pub struct Sha512 {
    state: Sha2State64
}

static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

static K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

const SHA2_32_BLOCK_LEN: usize = 64;
const SHA2_64_BLOCK_LEN: usize = 128;

struct Sha2State32 {
    h: [u32; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: usize
}

struct Sha2State64 {
    h: [u64; 8],
    buf: [u8; 256],
    buf_len: usize,
    total_len: usize
}

fn sha2_32_digest_oneshot(state: &mut Sha2State32, bytes: &[u8]) {

    let mut w: [u32; 64] = [0; 64];
    let mut i: usize = 0;

    for _ in ((bytes.len() >> 6)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((bytes[i + 0] as u32) << 24) |
                ((bytes[i + 1] as u32) << 16) |
                ((bytes[i + 2] as u32) <<  8) |
                 (bytes[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = state.h[0];
        let mut b: u32 = state.h[1];
        let mut c: u32 = state.h[2];
        let mut d: u32 = state.h[3];
        let mut e: u32 = state.h[4];
        let mut f: u32 = state.h[5];
        let mut g: u32 = state.h[6];
        let mut h: u32 = state.h[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state.h[0] = state.h[0].wrapping_add(a);
        state.h[1] = state.h[1].wrapping_add(b);
        state.h[2] = state.h[2].wrapping_add(c);
        state.h[3] = state.h[3].wrapping_add(d);
        state.h[4] = state.h[4].wrapping_add(e);
        state.h[5] = state.h[5].wrapping_add(f);
        state.h[6] = state.h[6].wrapping_add(g);
        state.h[7] = state.h[7].wrapping_add(h);

    }

    let n: usize = {
        let n: usize = 64 - (bytes.len() & 63);
        let n: usize = n + (if n < 9 { 64 } else { 0 });
        n + ((64 - (n & 63)) & 63)
    };

    state.buf[..(bytes.len() - i)].clone_from_slice(&bytes[i..(bytes.len())]);
    state.buf[bytes.len() - i] = 0x80;

    let bit_len: u64 = (bytes.len() as u64) << 3;
    state.buf[n - 8] = (bit_len >> 56) as u8;
    state.buf[n - 7] = (bit_len >> 48) as u8;
    state.buf[n - 6] = (bit_len >> 40) as u8;
    state.buf[n - 5] = (bit_len >> 32) as u8;
    state.buf[n - 4] = (bit_len >> 24) as u8;
    state.buf[n - 3] = (bit_len >> 16) as u8;
    state.buf[n - 2] = (bit_len >>  8) as u8;
    state.buf[n - 1] =  bit_len        as u8;

    i = 0;

    for _ in 0..(n >> 6) {

        for t in 0..16 {
            w[t] =
                ((state.buf[i + 0] as u32) << 24) |
                ((state.buf[i + 1] as u32) << 16) |
                ((state.buf[i + 2] as u32) <<  8) |
                 (state.buf[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma256_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u32 = state.h[0];
        let mut b: u32 = state.h[1];
        let mut c: u32 = state.h[2];
        let mut d: u32 = state.h[3];
        let mut e: u32 = state.h[4];
        let mut f: u32 = state.h[5];
        let mut g: u32 = state.h[6];
        let mut h: u32 = state.h[7];

        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(lsigma256_1(e))
                .wrapping_add(ch256(e, f, g))
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let t2: u32 = lsigma256_0(a)
                .wrapping_add(maj256(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state.h[0] = state.h[0].wrapping_add(a);
        state.h[1] = state.h[1].wrapping_add(b);
        state.h[2] = state.h[2].wrapping_add(c);
        state.h[3] = state.h[3].wrapping_add(d);
        state.h[4] = state.h[4].wrapping_add(e);
        state.h[5] = state.h[5].wrapping_add(f);
        state.h[6] = state.h[6].wrapping_add(g);
        state.h[7] = state.h[7].wrapping_add(h);

    }

}

/*
fn sha2_32_update(state: &mut Sha2State32, bytes: &[u8]) {

    let mut w: [u32; 64] = [0; 64];

    if (bytes.len() < SHA2_32_BLOCK_LEN - state.buf_len) {
        // memcpy(state->buf[state->buf_len], bytes, bytes.len());
        state.buf_len = state.buf_len - bytes.len();
        return;
    }

    let mut i = if state.buf_len == 0 { 0 } else { SHA2_32_BLOCK_LEN - state.buf_len };

    if i != 0 {

        // memcpy(state->buf[state->buf_len], bytes, i);

        for t in 0..16 {
            let j = i << 2;
            w[t] =
                ((state.buf[j + 0] as u32) << 24) |
                ((state.buf[j + 1] as u32) << 16) |
                ((state.buf[j + 2] as u32) <<  8) |
                 (state.buf[j + 3] as u32);
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2]) + w[t - 7] + ssigma256_0(w[t - 15]) + w[t - 16];
        }

        let mut a: u32 = state.h[0];
        let mut b: u32 = state.h[1];
        let mut c: u32 = state.h[2];
        let mut d: u32 = state.h[3];
        let mut e: u32 = state.h[4];
        let mut f: u32 = state.h[5];
        let mut g: u32 = state.h[6];
        let mut h: u32 = state.h[7];

        for t in 0..64 {
            let t1: u32 = h + lsigma256_1(e) + ch256(e, f, g) + K256[t] + w[t];
            let t2: u32 = lsigma256_0(a) + maj256(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state.h[0] = state.h[0] + a;
        state.h[1] = state.h[1] + b;
        state.h[2] = state.h[2] + c;
        state.h[3] = state.h[3] + d;
        state.h[4] = state.h[4] + e;
        state.h[5] = state.h[5] + f;
        state.h[6] = state.h[6] + g;
        state.h[7] = state.h[7] + h;

        state.total_len = state.total_len + state.buf_len;

    }

    for _ in (((bytes.len() - i) >> 6)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((bytes[i + 0] as u32) << 24) |
                ((bytes[i + 1] as u32) << 16) |
                ((bytes[i + 2] as u32) <<  8) |
                 (bytes[i + 3] as u32);
            i = i + 4;
        }

        for t in 16..64 {
            w[t] = ssigma256_1(w[t - 2]) + w[t - 7] + ssigma256_0(w[t - 15]) + w[t - 16];
        }

        let mut a: u32 = state.h[0];
        let mut b: u32 = state.h[1];
        let mut c: u32 = state.h[2];
        let mut d: u32 = state.h[3];
        let mut e: u32 = state.h[4];
        let mut f: u32 = state.h[5];
        let mut g: u32 = state.h[6];
        let mut h: u32 = state.h[7];

        for t in 0..64 {
            let t1: u32 = h + lsigma256_1(e) + ch256(e, f, g) + K256[t] + w[t];
            let t2: u32 = lsigma256_0(a) + maj256(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state.h[0] = state.h[0] + a;
        state.h[1] = state.h[1] + b;
        state.h[2] = state.h[2] + c;
        state.h[3] = state.h[3] + d;
        state.h[4] = state.h[4] + e;
        state.h[5] = state.h[5] + f;
        state.h[6] = state.h[6] + g;
        state.h[7] = state.h[7] + h;

    }

    if i < bytes.len() {
        state.buf_len = bytes.len() - i;
        // memcpy(state->buf, &bytes[i], state.buf_len);
    } else {
        state.buf_len = 0;
    }

}

fn sha2_32_digest(state: &mut Sha2State32, out: &mut [u32]) {

    out[0] = state.h[0];
    out[1] = state.h[0];
    out[2] = state.h[0];
    out[3] = state.h[0];
    out[4] = state.h[0];
    out[5] = state.h[0];
    out[0] = state.h[0];
    out[0] = state.h[0];

}
*/

fn sha2_64_digest_oneshot(state: &mut Sha2State64, bytes: &[u8]) {

    let mut w: [u64; 80] = [0; 80];
    let mut i: usize = 0;

    for _ in ((bytes.len() >> 7)..0).rev() {

        for t in 0..16 {
            w[t] =
                ((bytes[i + 0] as u64) << 56) |
                ((bytes[i + 1] as u64) << 48) |
                ((bytes[i + 2] as u64) << 40) |
                ((bytes[i + 3] as u64) << 32) |
                ((bytes[i + 4] as u64) << 24) |
                ((bytes[i + 5] as u64) << 16) |
                ((bytes[i + 6] as u64) <<  8) |
                 (bytes[i + 7] as u64);
            i = i + 8;
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = state.h[0];
        let mut b: u64 = state.h[1];
        let mut c: u64 = state.h[2];
        let mut d: u64 = state.h[3];
        let mut e: u64 = state.h[4];
        let mut f: u64 = state.h[5];
        let mut g: u64 = state.h[6];
        let mut h: u64 = state.h[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state.h[0] = state.h[0].wrapping_add(a);
        state.h[1] = state.h[1].wrapping_add(b);
        state.h[2] = state.h[2].wrapping_add(c);
        state.h[3] = state.h[3].wrapping_add(d);
        state.h[4] = state.h[4].wrapping_add(e);
        state.h[5] = state.h[5].wrapping_add(f);
        state.h[6] = state.h[6].wrapping_add(g);
        state.h[7] = state.h[7].wrapping_add(h);

    }

    let n: usize = {
        let n: usize = 128 - (bytes.len() & 127);
        let n: usize = n + (if n < 17 { 128 } else { 0 });
        n + ((128 - (n & 127)) & 127)
    };

    state.buf[..(bytes.len() - i)].clone_from_slice(&bytes[i..(bytes.len())]);
    state.buf[bytes.len() - i] = 0x80;

    let bit_len: u64 = (bytes.len() as u64) << 3;
    state.buf[n - 8] = (bit_len >> 56) as u8;
    state.buf[n - 7] = (bit_len >> 48) as u8;
    state.buf[n - 6] = (bit_len >> 40) as u8;
    state.buf[n - 5] = (bit_len >> 32) as u8;
    state.buf[n - 4] = (bit_len >> 24) as u8;
    state.buf[n - 3] = (bit_len >> 16) as u8;
    state.buf[n - 2] = (bit_len >>  8) as u8;
    state.buf[n - 1] =  bit_len        as u8;

    i = 0;

    for _ in 0..(n >> 7) {

        for t in 0..16 {
            w[t] =
                ((state.buf[i + 0] as u64) << 56) |
                ((state.buf[i + 1] as u64) << 48) |
                ((state.buf[i + 2] as u64) << 40) |
                ((state.buf[i + 3] as u64) << 32) |
                ((state.buf[i + 4] as u64) << 24) |
                ((state.buf[i + 5] as u64) << 16) |
                ((state.buf[i + 6] as u64) <<  8) |
                 (state.buf[i + 7] as u64);
            i = i + 8;
        }

        for t in 16..80 {
            w[t] = ssigma512_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssigma512_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a: u64 = state.h[0];
        let mut b: u64 = state.h[1];
        let mut c: u64 = state.h[2];
        let mut d: u64 = state.h[3];
        let mut e: u64 = state.h[4];
        let mut f: u64 = state.h[5];
        let mut g: u64 = state.h[6];
        let mut h: u64 = state.h[7];

        for t in 0..80 {
            let t1: u64 = h
                .wrapping_add(lsigma512_1(e))
                .wrapping_add(ch512(e, f, g))
                .wrapping_add(K512[t])
                .wrapping_add(w[t]);
            let t2: u64 = lsigma512_0(a)
                .wrapping_add(maj512(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state.h[0] = state.h[0].wrapping_add(a);
        state.h[1] = state.h[1].wrapping_add(b);
        state.h[2] = state.h[2].wrapping_add(c);
        state.h[3] = state.h[3].wrapping_add(d);
        state.h[4] = state.h[4].wrapping_add(e);
        state.h[5] = state.h[5].wrapping_add(f);
        state.h[6] = state.h[6].wrapping_add(g);
        state.h[7] = state.h[7].wrapping_add(h);

    }

}

impl Sha224 {

    const H0_0: u32 = 0xc1059ed8;
    const H0_1: u32 = 0x367cd507;
    const H0_2: u32 = 0x3070dd17;
    const H0_3: u32 = 0xf70e5939;
    const H0_4: u32 = 0xffc00b31;
    const H0_5: u32 = 0x68581511;
    const H0_6: u32 = 0x64f98fa7;
    const H0_7: u32 = 0xbefa4fa4;

}

impl Hash for Sha224 {

    fn digest_oneshot(bytes: &[u8], digest: &mut [u8]) -> Option<CryptoError> {

        let mut state: Sha2State32 = Sha2State32{
            h: [
                Sha224::H0_0,
                Sha224::H0_1,
                Sha224::H0_2,
                Sha224::H0_3,
                Sha224::H0_4,
                Sha224::H0_5,
                Sha224::H0_6,
                Sha224::H0_7
            ],
            buf: [0; 128],
            buf_len: 0,
            total_len: 0
        };

        sha2_32_digest_oneshot(&mut state, bytes);

        for i in 0..7 {
            let d: usize = i << 2;
            digest[d + 0] = (state.h[i] >> 24) as u8;
            digest[d + 1] = (state.h[i] >> 16) as u8;
            digest[d + 2] = (state.h[i] >>  8) as u8;
            digest[d + 3] =  state.h[i]        as u8;
        }

        return None;

    }

}

impl Sha256 {

    const H0_0: u32 = 0x6a09e667;
    const H0_1: u32 = 0xbb67ae85;
    const H0_2: u32 = 0x3c6ef372;
    const H0_3: u32 = 0xa54ff53a;
    const H0_4: u32 = 0x510e527f;
    const H0_5: u32 = 0x9b05688c;
    const H0_6: u32 = 0x1f83d9ab;
    const H0_7: u32 = 0x5be0cd19;

}

impl Hash for Sha256 {

    fn digest_oneshot(bytes: &[u8], digest: &mut [u8]) -> Option<CryptoError> {

        let mut state: Sha2State32 = Sha2State32{
            h: [
                Sha256::H0_0,
                Sha256::H0_1,
                Sha256::H0_2,
                Sha256::H0_3,
                Sha256::H0_4,
                Sha256::H0_5,
                Sha256::H0_6,
                Sha256::H0_7
            ],
            buf: [0; 128],
            buf_len: 0,
            total_len: 0
        };

        sha2_32_digest_oneshot(&mut state, bytes);

        for i in 0..8 {
            let d: usize = i << 2;
            digest[d + 0] = (state.h[i] >> 24) as u8;
            digest[d + 1] = (state.h[i] >> 16) as u8;
            digest[d + 2] = (state.h[i] >>  8) as u8;
            digest[d + 3] =  state.h[i]        as u8;
        }

        return None;

    }

}

impl Sha384 {

    const H0_0: u64 = 0xcbbb9d5dc1059ed8;
    const H0_1: u64 = 0x629a292a367cd507;
    const H0_2: u64 = 0x9159015a3070dd17;
    const H0_3: u64 = 0x152fecd8f70e5939;
    const H0_4: u64 = 0x67332667ffc00b31;
    const H0_5: u64 = 0x8eb44a8768581511;
    const H0_6: u64 = 0xdb0c2e0d64f98fa7;
    const H0_7: u64 = 0x47b5481dbefa4fa4;

}

impl Hash for Sha384 {

    fn digest_oneshot(bytes: &[u8], digest: &mut [u8]) -> Option<CryptoError> {

        let mut state: Sha2State64 = Sha2State64{
            h: [
                Sha384::H0_0,
                Sha384::H0_1,
                Sha384::H0_2,
                Sha384::H0_3,
                Sha384::H0_4,
                Sha384::H0_5,
                Sha384::H0_6,
                Sha384::H0_7
            ],
            buf: [0; 256],
            buf_len: 0,
            total_len: 0
        };

        sha2_64_digest_oneshot(&mut state, bytes);

        for i in 0..6 {
            let d: usize = i << 3;
            digest[d + 0] = (state.h[i] >> 56) as u8;
            digest[d + 1] = (state.h[i] >> 48) as u8;
            digest[d + 2] = (state.h[i] >> 40) as u8;
            digest[d + 3] = (state.h[i] >> 32) as u8;
            digest[d + 4] = (state.h[i] >> 24) as u8;
            digest[d + 5] = (state.h[i] >> 16) as u8;
            digest[d + 6] = (state.h[i] >>  8) as u8;
            digest[d + 7] =  state.h[i]        as u8;
        }

        return None;

    }

}

impl Sha512 {

    const H0_0: u64 = 0x6a09e667f3bcc908;
    const H0_1: u64 = 0xbb67ae8584caa73b;
    const H0_2: u64 = 0x3c6ef372fe94f82b;
    const H0_3: u64 = 0xa54ff53a5f1d36f1;
    const H0_4: u64 = 0x510e527fade682d1;
    const H0_5: u64 = 0x9b05688c2b3e6c1f;
    const H0_6: u64 = 0x1f83d9abfb41bd6b;
    const H0_7: u64 = 0x5be0cd19137e2179;

}

impl Hash for Sha512 {

    fn digest_oneshot(bytes: &[u8], digest: &mut [u8]) -> Option<CryptoError> {

        let mut state: Sha2State64 = Sha2State64{
            h: [
                Sha512::H0_0,
                Sha512::H0_1,
                Sha512::H0_2,
                Sha512::H0_3,
                Sha512::H0_4,
                Sha512::H0_5,
                Sha512::H0_6,
                Sha512::H0_7
            ],
            buf: [0; 256],
            buf_len: 0,
            total_len: 0
        };

        sha2_64_digest_oneshot(&mut state, bytes);

        for i in 0..8 {
            let d: usize = i << 3;
            digest[d + 0] = (state.h[i] >> 56) as u8;
            digest[d + 1] = (state.h[i] >> 48) as u8;
            digest[d + 2] = (state.h[i] >> 40) as u8;
            digest[d + 3] = (state.h[i] >> 32) as u8;
            digest[d + 4] = (state.h[i] >> 24) as u8;
            digest[d + 5] = (state.h[i] >> 16) as u8;
            digest[d + 6] = (state.h[i] >>  8) as u8;
            digest[d + 7] =  state.h[i]        as u8;
        }

        return None;

    }

}

fn ch256(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (!x & z);
}

fn maj256(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn lsigma256_0(x: u32) -> u32 {
    return ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));
}

fn lsigma256_1(x: u32) -> u32 {
    return ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));
}

fn ssigma256_0(x: u32) -> u32 {
    return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
}

fn ssigma256_1(x: u32) -> u32 {
    return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
}

fn ch512(x: u64, y: u64, z: u64) -> u64 {
    return (x & y) ^ (!x & z);
}

fn maj512(x: u64, y: u64, z: u64) -> u64 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn lsigma512_0(x: u64) -> u64 {
    return ((x >> 28) | (x << 36)) ^ ((x >> 34) | (x << 30)) ^ ((x >> 39) | (x << 25));
}

fn lsigma512_1(x: u64) -> u64 {
    return ((x >> 14) | (x << 50)) ^ ((x >> 18) | (x << 46)) ^ ((x >> 41) | (x << 23));
}

fn ssigma512_0(x: u64) -> u64 {
    return ((x >> 1) | (x << 63)) ^ ((x >> 8) | (x << 56)) ^ (x >> 7);
}

fn ssigma512_1(x: u64) -> u64 {
    return ((x >> 19) | (x << 45)) ^ ((x >> 61) | (x << 3)) ^ (x >> 6);
}