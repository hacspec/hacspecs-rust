#![allow(dead_code)]
// Import hacspec and all needed definitions.
use hacspec::prelude::*;

#[derive(Copy, Clone)]
enum Variant {
    SHA224 = 224,
    SHA256 = 256,
    SHA384 = 384,
    SHA512 = 512,
}

const block_size: usize = 64;
const k_size: usize = 64;
const len_size: usize = 8;
const hash_size: usize = Variant::SHA256 as usize / 8;

bytes!(Block, block_size);
bytes!(OpTableType, 12);
bytes!(digest_t, Variant::SHA256 as usize);
bytes!(h0_t, 8);
seq!(RoundConstantsTable, u32, k_size);
seq!(hash_t, WordT, 8);

type LenT = u64;
type WordT = u32;

// to_len : FunctionType = uint64
// len_to_bytes : FunctionType = bytes.from_uint64_be
// to_word : FunctionType = uint32
// bytes_to_words : FunctionType = bytes.to_uint32s_be
// words_to_bytes : FunctionType = bytes.from_uint32s_be

// const h0: hash_t = hash_t::from([
//     0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
//     0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);

fn ch(x: WordT, y: WordT, z: WordT) -> WordT {
    (x & y) ^ ((!x) & z)
}

fn maj(x: WordT, y: WordT, z: WordT) -> WordT {
    (x & y) ^ ((x & z) ^ (y & z))
}

fn sigma(x: WordT, i: usize, op: usize) -> WordT {
    let opTable = OpTableType::from([2, 13, 22, 6, 11, 25, 7, 18, 3, 17, 19, 10]);
    let tmp = if op == 0 {
        x >> opTable[3*i+2]
    } else {
        x.rotate_right(u32::from(opTable[3*i+2]))
    };
    x.rotate_right(u32::from(opTable[3*i])) ^
    x.rotate_right(u32::from(opTable[3*i+1])) ^
    tmp
}

fn schedule(block: Block) -> RoundConstantsTable {
    let b = block.to_uint32s_be();
    let mut s = RoundConstantsTable::new();
    for i in 0..k_size {
        if i < 16 {
            s[i] = b[i];
        }
        else {
            let t16 = s[i-16];
            let t15 = s[i-15];
            let t7  = s[i-7];
            let t2  = s[i-2];
            let s1  = sigma(t2, 3, 0);
            let s0  = sigma(t15, 2, 0);
            s[i] = s1 + t7 + s0 + t16;
        }
    }
    s
}

fn shuffle(ws:  RoundConstantsTable, hashi: hash_t) -> hash_t {
    let k_table = RoundConstantsTable::from([
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ]);

    let mut h = hashi;
    for i in 0..k_size {
        let a0 = h[0];
        let b0 = h[1];
        let c0 = h[2];
        let d0 = h[3];
        let e0 = h[4];
        let f0 = h[5];
        let g0 = h[6];
        let h0 = h[7];
    
        let t1 = h0 + sigma(e0,1,1) + ch(e0,f0,g0) + k_table[i] + ws[i];
        let t2 = sigma(a0,0,1) + maj(a0,b0,c0);
    
        h[0] = t1 + t2;
        h[1] = a0;
        h[2] = b0;
        h[3] = c0;
        h[4] = d0 + t1;
        h[5] = e0;
        h[6] = f0;
        h[7] = g0;
    }
    h
}

fn compress(block: Block, h_in: hash_t) -> hash_t {
    let s = schedule(block);
    let mut h = shuffle(s, h_in);
    for i in 0..8 {
        h[i] += h_in[i];
    }
    h
}

// fn truncate(b: bytes_t(v)) -> digest_t {
//     let result = array.create(hash_size, 0);
//     for i in 0..hash_size {
//         result[i] = b[i];
//     }
//     digest_t(result)
// }
