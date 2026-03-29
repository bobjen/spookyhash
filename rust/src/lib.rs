// SpookyHash: a 128-bit noncryptographic hash function
// By Bob Jenkins, public domain
// Rust translation by Claude, public domain

const SC_NUM_VARS: usize = 12;
const SC_BLOCK_SIZE: usize = SC_NUM_VARS * 8; // 96 bytes
const SC_BUF_SIZE: usize = 2 * SC_BLOCK_SIZE; // 192 bytes
const SC_CONST: u64 = 0xdeadbeefdeadbeef;

#[inline]
fn rot64(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}

#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

// Unaligned u64 read with no bounds check, matching C++ ALLOW_UNALIGNED_READS.
// Safety: caller must ensure off..off+8 is within buf.
#[inline]
unsafe fn read_u64_unchecked(buf: &[u8], off: usize) -> u64 {
    (buf.as_ptr().add(off) as *const u64).read_unaligned()
}

// This is used if the input is 96 bytes long or longer.
//
// The internal state is fully overwritten every 96 bytes.
// Every input bit appears to cause at least 128 bits of entropy
// before 96 other bytes are combined, when run forward or backward
//   For every input bit,
//   Two inputs differing in just that input bit
//   Where "differ" means xor or subtraction
//   And the base value is random
//   When run forward or backwards one Mix
// I tried 3 pairs of each; they all differed by at least 212 bits.
fn mix(data: &[u8], off: usize, h: &mut [u64; 12]) {
    // Safety: callers only call mix on complete 96-byte blocks within data.
    let d = |i: usize| unsafe { read_u64_unchecked(data, off + i * 8) };
    h[0]  = h[0].wrapping_add(d(0));   h[2]  ^= h[10]; h[11] ^= h[0];  h[0]  = rot64(h[0],  11); h[11] = h[11].wrapping_add(h[1]);
    h[1]  = h[1].wrapping_add(d(1));   h[3]  ^= h[11]; h[0]  ^= h[1];  h[1]  = rot64(h[1],  32); h[0]  = h[0].wrapping_add(h[2]);
    h[2]  = h[2].wrapping_add(d(2));   h[4]  ^= h[0];  h[1]  ^= h[2];  h[2]  = rot64(h[2],  43); h[1]  = h[1].wrapping_add(h[3]);
    h[3]  = h[3].wrapping_add(d(3));   h[5]  ^= h[1];  h[2]  ^= h[3];  h[3]  = rot64(h[3],  31); h[2]  = h[2].wrapping_add(h[4]);
    h[4]  = h[4].wrapping_add(d(4));   h[6]  ^= h[2];  h[3]  ^= h[4];  h[4]  = rot64(h[4],  17); h[3]  = h[3].wrapping_add(h[5]);
    h[5]  = h[5].wrapping_add(d(5));   h[7]  ^= h[3];  h[4]  ^= h[5];  h[5]  = rot64(h[5],  28); h[4]  = h[4].wrapping_add(h[6]);
    h[6]  = h[6].wrapping_add(d(6));   h[8]  ^= h[4];  h[5]  ^= h[6];  h[6]  = rot64(h[6],  39); h[5]  = h[5].wrapping_add(h[7]);
    h[7]  = h[7].wrapping_add(d(7));   h[9]  ^= h[5];  h[6]  ^= h[7];  h[7]  = rot64(h[7],  57); h[6]  = h[6].wrapping_add(h[8]);
    h[8]  = h[8].wrapping_add(d(8));   h[10] ^= h[6];  h[7]  ^= h[8];  h[8]  = rot64(h[8],  55); h[7]  = h[7].wrapping_add(h[9]);
    h[9]  = h[9].wrapping_add(d(9));   h[11] ^= h[7];  h[8]  ^= h[9];  h[9]  = rot64(h[9],  54); h[8]  = h[8].wrapping_add(h[10]);
    h[10] = h[10].wrapping_add(d(10)); h[0]  ^= h[8];  h[9]  ^= h[10]; h[10] = rot64(h[10], 22); h[9]  = h[9].wrapping_add(h[11]);
    h[11] = h[11].wrapping_add(d(11)); h[1]  ^= h[9];  h[10] ^= h[11]; h[11] = rot64(h[11], 46); h[10] = h[10].wrapping_add(h[0]);
}

// Mix all 12 inputs together so that h0, h1 are a hash of them all.
//
// For two inputs differing in just the input bits
// Where "differ" means xor or subtraction
// And the base value is random, or a counting value starting at that bit
// The final result will have each bit of h0, h1 flip
// For every input bit,
// with probability 50 +- .3%
// For every pair of input bits,
// with probability 50 +- 3%
//
// This does not rely on the last Mix() call having already mixed some.
// Two iterations was almost good enough for a 64-bit result, but a
// 128-bit result is reported, so End() does three iterations.
fn end_partial(h: &mut [u64; 12]) {
    h[11] = h[11].wrapping_add(h[1]);  h[2]  ^= h[11]; h[1]  = rot64(h[1],  44);
    h[0]  = h[0].wrapping_add(h[2]);   h[3]  ^= h[0];  h[2]  = rot64(h[2],  15);
    h[1]  = h[1].wrapping_add(h[3]);   h[4]  ^= h[1];  h[3]  = rot64(h[3],  34);
    h[2]  = h[2].wrapping_add(h[4]);   h[5]  ^= h[2];  h[4]  = rot64(h[4],  21);
    h[3]  = h[3].wrapping_add(h[5]);   h[6]  ^= h[3];  h[5]  = rot64(h[5],  38);
    h[4]  = h[4].wrapping_add(h[6]);   h[7]  ^= h[4];  h[6]  = rot64(h[6],  33);
    h[5]  = h[5].wrapping_add(h[7]);   h[8]  ^= h[5];  h[7]  = rot64(h[7],  10);
    h[6]  = h[6].wrapping_add(h[8]);   h[9]  ^= h[6];  h[8]  = rot64(h[8],  13);
    h[7]  = h[7].wrapping_add(h[9]);   h[10] ^= h[7];  h[9]  = rot64(h[9],  38);
    h[8]  = h[8].wrapping_add(h[10]);  h[11] ^= h[8];  h[10] = rot64(h[10], 53);
    h[9]  = h[9].wrapping_add(h[11]);  h[0]  ^= h[9];  h[11] = rot64(h[11], 42);
    h[10] = h[10].wrapping_add(h[0]);  h[1]  ^= h[10]; h[0]  = rot64(h[0],  54);
}

fn mix_end(data: &[u8], off: usize, h: &mut [u64; 12]) {
    // Safety: callers pass a SC_BLOCK_SIZE (96-byte) buffer fully initialized.
    for i in 0..12 {
        h[i] = h[i].wrapping_add(unsafe { read_u64_unchecked(data, off + i * 8) });
    }
    end_partial(h);
    end_partial(h);
    end_partial(h);
}

// The goal is for each bit of the input to expand into 128 bits of
//   apparent entropy before it is fully overwritten.
// n trials both set and cleared at least m bits of h0 h1 h2 h3
//   n: 2   m: 29
//   n: 3   m: 46
//   n: 4   m: 57
//   n: 5   m: 107
//   n: 6   m: 146
//   n: 7   m: 152
// when run forwards or backwards
// for all 1-bit and 2-bit diffs
// with diffs defined by either xor or subtraction
// with a base of all zeros plus a counter, or plus another bit, or random
fn short_mix(h: &mut [u64; 4]) {
    h[2] = rot64(h[2], 50); h[2] = h[2].wrapping_add(h[3]); h[0] ^= h[2];
    h[3] = rot64(h[3], 52); h[3] = h[3].wrapping_add(h[0]); h[1] ^= h[3];
    h[0] = rot64(h[0], 30); h[0] = h[0].wrapping_add(h[1]); h[2] ^= h[0];
    h[1] = rot64(h[1], 41); h[1] = h[1].wrapping_add(h[2]); h[3] ^= h[1];
    h[2] = rot64(h[2], 54); h[2] = h[2].wrapping_add(h[3]); h[0] ^= h[2];
    h[3] = rot64(h[3], 48); h[3] = h[3].wrapping_add(h[0]); h[1] ^= h[3];
    h[0] = rot64(h[0], 38); h[0] = h[0].wrapping_add(h[1]); h[2] ^= h[0];
    h[1] = rot64(h[1], 37); h[1] = h[1].wrapping_add(h[2]); h[3] ^= h[1];
    h[2] = rot64(h[2], 62); h[2] = h[2].wrapping_add(h[3]); h[0] ^= h[2];
    h[3] = rot64(h[3], 34); h[3] = h[3].wrapping_add(h[0]); h[1] ^= h[3];
    h[0] = rot64(h[0],  5); h[0] = h[0].wrapping_add(h[1]); h[2] ^= h[0];
    h[1] = rot64(h[1], 36); h[1] = h[1].wrapping_add(h[2]); h[3] ^= h[1];
}

// Mix all 4 inputs together so that h0, h1 are a hash of them all.
//
// For two inputs differing in just the input bits
// Where "differ" means xor or subtraction
// And the base value is random, or a counting value starting at that bit
// The final result will have each bit of h0, h1 flip
// For every input bit,
// with probability 50 +- .3% (it is probably better than that)
// For every pair of input bits,
// with probability 50 +- .75% (the worst case is approximately that)
fn short_end(h: &mut [u64; 4]) {
    h[3] ^= h[2]; h[2] = rot64(h[2], 15); h[3] = h[3].wrapping_add(h[2]);
    h[0] ^= h[3]; h[3] = rot64(h[3], 52); h[0] = h[0].wrapping_add(h[3]);
    h[1] ^= h[0]; h[0] = rot64(h[0], 26); h[1] = h[1].wrapping_add(h[0]);
    h[2] ^= h[1]; h[1] = rot64(h[1], 51); h[2] = h[2].wrapping_add(h[1]);
    h[3] ^= h[2]; h[2] = rot64(h[2], 28); h[3] = h[3].wrapping_add(h[2]);
    h[0] ^= h[3]; h[3] = rot64(h[3],  9); h[0] = h[0].wrapping_add(h[3]);
    h[1] ^= h[0]; h[0] = rot64(h[0], 47); h[1] = h[1].wrapping_add(h[0]);
    h[2] ^= h[1]; h[1] = rot64(h[1], 54); h[2] = h[2].wrapping_add(h[1]);
    h[3] ^= h[2]; h[2] = rot64(h[2], 32); h[3] = h[3].wrapping_add(h[2]);
    h[0] ^= h[3]; h[3] = rot64(h[3], 25); h[0] = h[0].wrapping_add(h[3]);
    h[1] ^= h[0]; h[0] = rot64(h[0], 63); h[1] = h[1].wrapping_add(h[0]);
}

// Used for messages < 192 bytes.
fn short(message: &[u8], hash1: &mut u64, hash2: &mut u64) {
    let length = message.len();
    let total_remainder = length % 32;

    // h = [a, b, c, d]
    let mut h: [u64; 4] = [*hash1, *hash2, SC_CONST, SC_CONST];

    let mut offset = 0usize;
    if length > 15 {
        let block_end = (length / 32) * 32;
        // Safety: block_end = (length/32)*32 <= length, and each read is within a
        // complete 32-byte block, so all offsets are within message.
        while offset < block_end {
            h[2] = h[2].wrapping_add(unsafe { read_u64_unchecked(message, offset) });
            h[3] = h[3].wrapping_add(unsafe { read_u64_unchecked(message, offset + 8) });
            short_mix(&mut h);
            h[0] = h[0].wrapping_add(unsafe { read_u64_unchecked(message, offset + 16) });
            h[1] = h[1].wrapping_add(unsafe { read_u64_unchecked(message, offset + 24) });
            offset += 32;
        }
        if total_remainder >= 16 {
            // Safety: total_remainder >= 16 means at least 16 more bytes remain.
            h[2] = h[2].wrapping_add(unsafe { read_u64_unchecked(message, offset) });
            h[3] = h[3].wrapping_add(unsafe { read_u64_unchecked(message, offset + 8) });
            short_mix(&mut h);
            offset += 16;
        }
    }

    let tail_rem = if length > 15 && total_remainder >= 16 {
        total_remainder - 16
    } else {
        total_remainder
    };
    let tail = &message[offset..];

    // Mix in length (in high byte of d) and the remaining 0..15 bytes.
    h[3] = h[3].wrapping_add((length as u64) << 56);
    match tail_rem {
        15 => {
            h[3] = h[3]
                .wrapping_add((tail[14] as u64) << 48)
                .wrapping_add((tail[13] as u64) << 40)
                .wrapping_add((tail[12] as u64) << 32)
                .wrapping_add(read_u32(tail, 8) as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        14 => {
            h[3] = h[3]
                .wrapping_add((tail[13] as u64) << 40)
                .wrapping_add((tail[12] as u64) << 32)
                .wrapping_add(read_u32(tail, 8) as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        13 => {
            h[3] = h[3]
                .wrapping_add((tail[12] as u64) << 32)
                .wrapping_add(read_u32(tail, 8) as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        12 => {
            h[3] = h[3].wrapping_add(read_u32(tail, 8) as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        11 => {
            h[3] = h[3]
                .wrapping_add((tail[10] as u64) << 16)
                .wrapping_add((tail[9] as u64) << 8)
                .wrapping_add(tail[8] as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        10 => {
            h[3] = h[3]
                .wrapping_add((tail[9] as u64) << 8)
                .wrapping_add(tail[8] as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        9 => {
            h[3] = h[3].wrapping_add(tail[8] as u64);
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        8 => {
            h[2] = h[2].wrapping_add(read_u64(tail, 0));
        }
        7 => {
            h[2] = h[2]
                .wrapping_add((tail[6] as u64) << 48)
                .wrapping_add((tail[5] as u64) << 40)
                .wrapping_add((tail[4] as u64) << 32)
                .wrapping_add(read_u32(tail, 0) as u64);
        }
        6 => {
            h[2] = h[2]
                .wrapping_add((tail[5] as u64) << 40)
                .wrapping_add((tail[4] as u64) << 32)
                .wrapping_add(read_u32(tail, 0) as u64);
        }
        5 => {
            h[2] = h[2]
                .wrapping_add((tail[4] as u64) << 32)
                .wrapping_add(read_u32(tail, 0) as u64);
        }
        4 => {
            h[2] = h[2].wrapping_add(read_u32(tail, 0) as u64);
        }
        3 => {
            h[2] = h[2]
                .wrapping_add((tail[2] as u64) << 16)
                .wrapping_add((tail[1] as u64) << 8)
                .wrapping_add(tail[0] as u64);
        }
        2 => {
            h[2] = h[2]
                .wrapping_add((tail[1] as u64) << 8)
                .wrapping_add(tail[0] as u64);
        }
        1 => {
            h[2] = h[2].wrapping_add(tail[0] as u64);
        }
        0 => {
            h[2] = h[2].wrapping_add(SC_CONST);
            h[3] = h[3].wrapping_add(SC_CONST);
        }
        _ => unreachable!(),
    }
    short_end(&mut h);
    *hash1 = h[0];
    *hash2 = h[1];
}

/// Hash a message in one call, producing 128-bit output.
/// hash1 and hash2 are in/out: pass seeds in, get hash values out.
pub fn hash128(message: &[u8], hash1: &mut u64, hash2: &mut u64) {
    let length = message.len();
    if length < SC_BUF_SIZE {
        short(message, hash1, hash2);
        return;
    }

    let mut h = [0u64; 12];
    h[0] = *hash1; h[3] = *hash1; h[6] = *hash1; h[9]  = *hash1;
    h[1] = *hash2; h[4] = *hash2; h[7] = *hash2; h[10] = *hash2;
    h[2] = SC_CONST; h[5] = SC_CONST; h[8] = SC_CONST; h[11] = SC_CONST;

    let num_blocks = length / SC_BLOCK_SIZE;
    for i in 0..num_blocks {
        mix(message, i * SC_BLOCK_SIZE, &mut h);
    }

    let remainder = length - num_blocks * SC_BLOCK_SIZE;
    let mut buf = [0u8; SC_BLOCK_SIZE];
    buf[..remainder].copy_from_slice(&message[num_blocks * SC_BLOCK_SIZE..]);
    buf[SC_BLOCK_SIZE - 1] = remainder as u8;

    mix_end(&buf, 0, &mut h);
    *hash1 = h[0];
    *hash2 = h[1];
}

/// Hash a message in one call, returning a 64-bit value.
pub fn hash64(message: &[u8], seed: u64) -> u64 {
    let mut h1 = seed;
    let mut h2 = seed;
    hash128(message, &mut h1, &mut h2);
    h1
}

/// Hash a message in one call, returning a 32-bit value.
pub fn hash32(message: &[u8], seed: u32) -> u32 {
    let mut h1 = seed as u64;
    let mut h2 = seed as u64;
    hash128(message, &mut h1, &mut h2);
    h1 as u32
}

/// Incremental (streaming) SpookyHash state.
pub struct SpookyHash {
    data: [u8; SC_BUF_SIZE],
    state: [u64; SC_NUM_VARS],
    length: usize,
    remainder: usize,
}

impl SpookyHash {
    pub fn new() -> Self {
        SpookyHash {
            data: [0; SC_BUF_SIZE],
            state: [0; SC_NUM_VARS],
            length: 0,
            remainder: 0,
        }
    }

    /// Initialize state with two 64-bit seeds.
    pub fn init(&mut self, seed1: u64, seed2: u64) {
        self.length = 0;
        self.remainder = 0;
        self.state[0] = seed1;
        self.state[1] = seed2;
    }

    /// Feed a message fragment into the hash state.
    pub fn update(&mut self, message: &[u8]) {
        let length = message.len();
        let new_length = length + self.remainder;

        // Not enough data to fill buffer yet; stash and return.
        if new_length < SC_BUF_SIZE {
            self.data[self.remainder..self.remainder + length].copy_from_slice(message);
            self.length += length;
            self.remainder = new_length;
            return;
        }

        let mut h = [0u64; 12];
        if self.length < SC_BUF_SIZE {
            // First time going long: init all 12 state vars from just seed1, seed2.
            h[0] = self.state[0]; h[3] = self.state[0]; h[6] = self.state[0]; h[9]  = self.state[0];
            h[1] = self.state[1]; h[4] = self.state[1]; h[7] = self.state[1]; h[10] = self.state[1];
            h[2] = SC_CONST; h[5] = SC_CONST; h[8] = SC_CONST; h[11] = SC_CONST;
        } else {
            h = self.state;
        }
        self.length += length;

        let mut msg_offset = 0usize;
        if self.remainder > 0 {
            // Complete the buffer with the start of this message, then mix it.
            let prefix = SC_BUF_SIZE - self.remainder;
            self.data[self.remainder..SC_BUF_SIZE].copy_from_slice(&message[..prefix]);
            mix(&self.data.clone(), 0, &mut h);
            mix(&self.data.clone(), SC_BLOCK_SIZE, &mut h);
            msg_offset = prefix;
        }

        let remaining = length - msg_offset;
        let num_blocks = remaining / SC_BLOCK_SIZE;
        for i in 0..num_blocks {
            mix(message, msg_offset + i * SC_BLOCK_SIZE, &mut h);
        }

        // Stash leftover bytes.
        let tail_start = msg_offset + num_blocks * SC_BLOCK_SIZE;
        let tail_size = remaining - num_blocks * SC_BLOCK_SIZE;
        self.remainder = tail_size;
        self.data[..tail_size].copy_from_slice(&message[tail_start..tail_start + tail_size]);

        self.state = h;
    }

    /// Compute the final 128-bit hash. Does not modify state.
    pub fn final_hash(&self) -> (u64, u64) {
        if self.length < SC_BUF_SIZE {
            let mut h1 = self.state[0];
            let mut h2 = self.state[1];
            short(&self.data[..self.length], &mut h1, &mut h2);
            return (h1, h2);
        }

        let remainder = self.remainder;
        let mut h: [u64; 12] = self.state;

        if remainder >= SC_BLOCK_SIZE {
            // data buffer holds two blocks; mix the first complete one.
            mix(&self.data, 0, &mut h);
            let sub_rem = remainder - SC_BLOCK_SIZE;
            let mut buf = [0u8; SC_BLOCK_SIZE];
            buf[..sub_rem].copy_from_slice(&self.data[SC_BLOCK_SIZE..SC_BLOCK_SIZE + sub_rem]);
            buf[SC_BLOCK_SIZE - 1] = sub_rem as u8;
            mix_end(&buf, 0, &mut h);
        } else {
            let mut buf = [0u8; SC_BLOCK_SIZE];
            buf[..remainder].copy_from_slice(&self.data[..remainder]);
            buf[SC_BLOCK_SIZE - 1] = remainder as u8;
            mix_end(&buf, 0, &mut h);
        }

        (h[0], h[1])
    }
}

impl Default for SpookyHash {
    fn default() -> Self {
        Self::new()
    }
}
