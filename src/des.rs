/// Represents an DES key as an array of 8 bytes.
pub type Key = [u8; 8];

/// The first bit in a 64-bit integer.
const FIRST_BIT: u64 = 1 << 63;
/// The size of a DES key divided by 2.
const HALF_KEY_SIZE: i64 = KEY_SIZE / 2;
/// The size of a DES key in bytes.
const KEY_SIZE: i64 = 56;

pub mod des_alg {
    use super::*;

    #[inline]
    pub fn ecb_encrypt(cipher: &[u8], key: &Vec<Key>) -> (Vec<u8>, Option<Vec<u8>>) {
        let key = key_to_u64(&key[0]);
        let subkeys = compute_subkeys(key);

        (des_ecb(&cipher, &subkeys), None)
    }

    #[inline]
    pub fn ecb_decrypt(cipher: &[u8], key: &Vec<Key>) -> (Vec<u8>, Option<Vec<u8>>) {
        let key = key_to_u64(&key[0]);
        let subkeys = compute_subkeys(key).into_iter().rev().collect::<Vec<_>>();

        (des_ecb(&cipher, &subkeys), None)
    }

    #[inline]
    pub fn cbc_encrypt(
        message: &[u8],
        key: &Vec<Key>,
        iv: &[u8],
        last_block: Option<Vec<u8>>,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let key = key_to_u64(&key[0]);
        let subkeys = compute_subkeys(key);

        des_cbc(&message, &subkeys, &iv, last_block)
    }

    #[inline]
    pub fn cbc_decrypt(
        cipher: &[u8],
        key: &Vec<Key>,
        iv: &[u8],
        last_block: Option<Vec<u8>>,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let key = key_to_u64(&key[0]);
        let subkeys = compute_subkeys(key).into_iter().rev().collect::<Vec<_>>();

        des_cbc_decrypt(&cipher, &subkeys, &iv, last_block)
    }
}

/// Utility functions for the Data Encryption Standard (DES) algorithm.
pub mod utils {
    use super::*;

    /// # Circular Left Shift
    /// Perform a circular left shift on a width of `HALF_KEY_SIZE`.
    ///
    /// ## Parameters
    /// - `n1`: The first 64-bit value.
    /// - `n2`: The second 64-bit value.
    /// - `shift_count`: The number of bits to shift.
    ///
    /// ## Returns
    /// A tuple containing the results of the circular left shift on `n1` and `n2`.
    fn circular_left_shift(n1: u64, n2: u64, shift_count: i64) -> (u64, u64) {
        let mut new_value1 = n1;
        let mut new_value2 = n2;
        for _ in 0..shift_count {
            let first_bit = new_value1 & FIRST_BIT;
            new_value1 = (new_value1 << 1) | (first_bit >> (HALF_KEY_SIZE - 1));
            let first_bit = new_value2 & FIRST_BIT;
            new_value2 = (new_value2 << 1) | (first_bit >> (HALF_KEY_SIZE - 1));
        }
        (new_value1, new_value2)
    }

    /// # Compute Subkeys
    /// Generate 16 subkeys for the DES algorithm.
    ///
    /// ## Parameters
    /// - `key`: The initial 64-bit key.
    ///
    /// ## Returns
    /// A vector containing 16 subkeys.
    pub(crate) fn compute_subkeys(key: u64) -> Vec<u64> {
        let table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
        let k0 = pc1(key);
        let mut subkeys = vec![k0];

        for shift_count in &table {
            let last_key = *subkeys.last().unwrap();
            let last_ci = last_key & 0xFFFFFFF000000000;
            let last_di = last_key << HALF_KEY_SIZE;
            let (ci, di) = circular_left_shift(last_ci, last_di, *shift_count);
            let current_key = ci | (di >> HALF_KEY_SIZE);
            subkeys.push(current_key);
        }

        subkeys.remove(0);
        subkeys.iter().map(|&n| pc2(n)).collect()
    }

    /// # DES ECB Encryption
    /// Encrypt a message using DES in Electronic Codebook (ECB) mode.
    ///
    /// ## Parameters
    /// - `message`: The input message as a slice of bytes.
    /// - `subkeys`: A vector containing 16 subkeys generated from the initial key.
    ///
    /// ## Returns
    /// A vector of bytes representing the encrypted message.    
    #[inline]
    pub(crate) fn des_ecb(message: &[u8], subkeys: &Vec<u64>) -> Vec<u8> {
        let message_len = message.len();
        let message = message_to_u64s(message);

        let blocks = {
            let this = message.iter().map(|&block| {
                let permuted = ip(block);
                let mut li = permuted & 0xFFFFFFFF00000000;
                let mut ri = permuted << 32;

                for subkey in subkeys {
                    let last_li = li;
                    li = ri;
                    ri = last_li ^ feistel(ri, *subkey);
                }

                let r16l16 = ri | (li >> 32);
                to_u8_vec(fp(r16l16))
            });
            let mut collection = Vec::new();
            collection.extend(this);
            collection
        };

        let mut result = Vec::with_capacity(message_len);
        for mut block in blocks.into_iter() {
            result.append(&mut block);
        }
        result
    }

    /// # DES CBC Encryption
    /// Encrypt a message using DES in Cipher Block Chaining (CBC) mode with an Initialization Vector (IV).
    ///
    /// ## Parameters
    /// - `message`: The input message as a slice of bytes.
    /// - `subkeys`: A vector containing 16 subkeys generated from the initial key.
    /// - `iv`: The Initialization Vector (IV) as a slice of bytes.
    ///
    /// ## Returns
    /// A vector of bytes representing the encrypted message.    
    #[inline]
    pub(crate) fn des_cbc(
        message: &[u8],
        subkeys: &Vec<u64>,
        iv: &[u8],
        mut last: Option<Vec<u8>>,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let message_len = message.len();
        let message = message_to_u64s(message);

        let mut blocks = vec![];
        for &block in message.iter() {
            let block_xor = block ^ u64_from_bytes(&last.unwrap_or(iv.to_vec()));

            let permuted = ip(block_xor);
            let mut li = permuted & 0xFFFFFFFF00000000;
            let mut ri = permuted << 32;

            for subkey in subkeys {
                let last_li = li;
                li = ri;
                ri = last_li ^ feistel(ri, *subkey);
            }

            let r16l16 = ri | (li >> 32);
            let encrypted_block = to_u8_vec(fp(r16l16));

            blocks.push(encrypted_block.clone());

            last = Some(encrypted_block);
        }

        let mut result = Vec::with_capacity(message_len);
        for mut block in blocks.into_iter() {
            result.append(&mut block);
        }

        (result, last)
    }

    /// # DES CBC Decryption
    /// Decrypt a message using DES in Cipher Block Chaining (CBC) mode with an Initialization Vector (IV).
    ///
    /// ## Parameters
    /// - `message`: The input message as a slice of bytes.
    /// - `subkeys`: A vector containing 16 subkeys generated from the initial key.
    /// - `iv`: The Initialization Vector (IV) as a slice of bytes.
    ///
    /// ## Returns
    /// A vector of bytes representing the decrypted message.    
    #[inline]
    pub(crate) fn des_cbc_decrypt(
        message: &[u8],
        subkeys: &Vec<u64>,
        iv: &[u8],
        mut last: Option<Vec<u8>>,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let message_len = message.len();
        let message = message_to_u64s(message);

        let mut blocks = vec![];
        for &block in message.iter() {
            let block_xor = block ^ u64_from_bytes(&last.unwrap_or(iv.to_vec()));

            let permuted = ip(block_xor);
            let mut li = permuted & 0xFFFFFFFF00000000;
            let mut ri = permuted << 32;

            for subkey in subkeys {
                let last_li = li;
                li = ri;
                ri = last_li ^ feistel(ri, *subkey);
            }

            let r16l16 = ri | (li >> 32);
            let encrypted_block = to_u8_vec(fp(r16l16));

            blocks.push(encrypted_block.clone());

            last = Some(encrypted_block);
        }

        let mut result = Vec::with_capacity(message_len);
        for mut block in blocks.into_iter() {
            result.append(&mut block);
        }

        (result, last)
    }

    /// # Delta Swap
    /// Swap bits in `a` using a delta swap.
    ///
    /// ## Parameters
    /// - `a`: The input 64-bit integer.
    /// - `delta`: The amount to shift for the swap.
    /// - `mask`: The mask to apply during the swap.
    ///
    /// ## Returns
    /// The result of the delta swap operation on the input integer.    
    #[inline]
    fn delta_swap(a: u64, delta: u64, mask: u64) -> u64 {
        let b = (a ^ (a >> delta)) & mask;
        a ^ b ^ (b << delta)
    }

    /// # E Function
    /// Swap bits using the E table.
    ///
    /// ## Parameters
    /// - `block`: The 32-bit input block to swap bits.
    ///
    /// ## Returns
    /// The result of swapping bits using the E table.    
    #[inline]
    fn e(block: u64) -> u64 {
        const BLOCK_LEN: usize = 32;
        const RESULT_LEN: usize = 48;

        let b1 = (block << (BLOCK_LEN - 1)) & 0x8000000000000000;
        let b2 = (block >> 1) & 0x7C00000000000000;
        let b3 = (block >> 3) & 0x03F0000000000000;
        let b4 = (block >> 5) & 0x000FC00000000000;
        let b5 = (block >> 7) & 0x00003F0000000000;
        let b6 = (block >> 9) & 0x000000FC00000000;
        let b7 = (block >> 11) & 0x00000003F0000000;
        let b8 = (block >> 13) & 0x000000000FC00000;
        let b9 = (block >> 15) & 0x00000000003E0000;
        let b10 = (block >> (RESULT_LEN - 1)) & 0x0000000000010000;
        b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9 | b10
    }

    /// # Feistel Function
    /// Feistel function used in DES encryption.
    ///
    /// ## Parameters
    /// - `half_block`: The 32-bit input block for the Feistel function.
    /// - `subkey`: The subkey used in the Feistel function.
    ///
    /// ## Returns
    /// The result of applying the Feistel function on the input block.
    fn feistel(half_block: u64, subkey: u64) -> u64 {
        let expanded = e(half_block);
        let mut intermediate = expanded ^ subkey;
        let mut result = 0;

        for i in 0..8 {
            let block = (intermediate & 0xFC00000000000000) >> 58;
            intermediate <<= 6;
            result <<= 4;
            result |= s(i, block);
        }

        p(result << 32)
    }

    /// # FP Function
    /// Swap bits using the reverse FP table.
    ///
    /// ## Parameters
    /// - `message`: The 64-bit input message to swap bits.
    ///
    /// ## Returns
    /// The result of swapping bits using the reverse FP table.
    fn fp(message: u64) -> u64 {
        let message = delta_swap(message, 24, 0x000000FF000000FF);
        let message = delta_swap(message, 24, 0x00000000FF00FF00);
        let message = delta_swap(message, 36, 0x000000000F0F0F0F);
        let message = delta_swap(message, 18, 0x0000333300003333);
        delta_swap(message, 9, 0x0055005500550055)
    }

    /// # IP Function
    /// Swap bits using the IP table.
    ///
    /// ## Parameters
    /// - `message`: The 64-bit input message to swap bits.
    ///
    /// ## Returns
    /// The result of swapping bits using the IP table.
    fn ip(message: u64) -> u64 {
        let message = delta_swap(message, 9, 0x0055005500550055);
        let message = delta_swap(message, 18, 0x0000333300003333);
        let message = delta_swap(message, 36, 0x000000000F0F0F0F);
        let message = delta_swap(message, 24, 0x00000000FF00FF00);
        delta_swap(message, 24, 0x000000FF000000FF)
    }

    /// # P Function
    /// Swap bits using the P table.
    ///
    /// ## Parameters
    /// - `block`: The 32-bit input block to swap bits.
    ///
    /// ## Returns
    /// The result of swapping bits using the P table.
    fn p(block: u64) -> u64 {
        let block = block.rotate_left(44);
        let b1 = (block & 0x0000000000200000) << 32;
        let b2 = (block & 0x0000000000480000) << 13;
        let b3 = (block & 0x0000088000000000) << 12;
        let b4 = (block & 0x0000002020120000) << 25;
        let b5 = (block & 0x0000000442000000) << 14;
        let b6 = (block & 0x0000000001800000) << 37;
        let b7 = (block & 0x0000000004000000) << 24;
        let b8 = (block & 0x0000020280015000).wrapping_mul(0x0000020080800083) & 0x02000a6400000000;
        let b9 = (block.rotate_left(29) & 0x01001400000000aa).wrapping_mul(0x0000210210008081)
            & 0x0902c01200000000;
        let b10 =
            (block & 0x0000000910040000).wrapping_mul(0x0000000c04000020) & 0x8410010000000000;
        b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9 | b10
    }

    /// # PC1 Function
    /// Swap bits using the PC-1 table.
    ///
    /// ## Parameters
    /// - `key`: The 64-bit input key to swap bits.
    ///
    /// ## Returns
    /// The result of swapping bits using the PC-1 table.
    fn pc1(key: u64) -> u64 {
        let key = delta_swap(key, 2, 0x3333000033330000);
        let key = delta_swap(key, 4, 0x0f0f0f0f00000000);
        let key = delta_swap(key, 8, 0x009a000a00a200a8);
        let key = delta_swap(key, 16, 0x00006c6c0000cccc);
        let key = delta_swap(key, 1, 0x1045500500550550);
        let key = delta_swap(key, 32, 0x00000000f0f0f5fa);
        let key = delta_swap(key, 8, 0x00550055006a00aa);
        let key = delta_swap(key, 2, 0x0000333330000300);
        key & 0xFFFFFFFFFFFFFF00
    }

    /// # PC2 Function
    /// Swap bits using the PC-2 table.
    ///
    /// ## Parameters
    /// - `key`: The 56-bit input key to swap bits.
    ///
    /// ## Returns
    /// The result of swapping bits using the PC-2 table.
    fn pc2(key: u64) -> u64 {
        let key = key.rotate_left(61);
        let b1 = (key & 0x0021000002000000) >> 7;
        let b2 = (key & 0x0008020010080000) << 1;
        let b3 = key & 0x0002200000000000;
        let b4 = (key & 0x0000000000100020) << 19;
        let b5 = (key.rotate_left(54) & 0x0005312400000011).wrapping_mul(0x0000000094200201)
            & 0xea40100880000000;
        let b6 = (key.rotate_left(7) & 0x0022110000012001).wrapping_mul(0x0001000000610006)
            & 0x1185004400000000;
        let b7 = (key.rotate_left(6) & 0x0000520040200002).wrapping_mul(0x00000080000000c1)
            & 0x0028811000200000;
        let b8 = (key & 0x01000004c0011100).wrapping_mul(0x0000000000004284) & 0x0400082244400000;
        let b9 = (key.rotate_left(60) & 0x0000000000820280).wrapping_mul(0x0000000000089001)
            & 0x0000000110880000;
        let b10 = (key.rotate_left(49) & 0x0000000000024084).wrapping_mul(0x0000000002040005)
            & 0x000000000a030000;
        b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9 | b10
    }

    /// # S Box Function
    /// Produce 4 bits using an S box.
    ///
    /// ## Parameters
    /// - `box_id`: The index of the S box.
    /// - `block`: The 6-bit input block to produce 4 bits.
    ///
    /// ## Returns
    /// The 4-bit output produced by the S box.
    fn s(box_id: usize, block: u64) -> u64 {
        const TABLES: [[[u64; 16]; 4]; 8] = [
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            ],
            [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            ],
            [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            ],
            [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            ],
            [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            ],
            [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            ],
            [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            ],
            [
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
            ],
        ];
        let i = ((block & 0x20) >> 4 | (block & 1)) as usize;
        let j = ((block & 0x1E) >> 1) as usize;

        TABLES[box_id][i][j]
    }

    /// # Key to u64
    /// Convert a `Key` (array of 8 bytes) to a 64-bit integer.
    ///
    /// ## Parameters
    /// - `key`: The `Key` array to convert.
    ///
    /// ## Returns
    /// A 64-bit integer representing the given `Key`.
    pub(crate) fn key_to_u64(key: &Key) -> u64 {
        let mut result = 0;
        for &part in key {
            result <<= 8;
            result += part as u64;
        }

        result
    }

    /// # To Byte Vector
    /// Convert a 64-bit number to a vector of 8 bytes.
    ///
    /// ## Parameters
    /// - `num`: The 64-bit number to convert.
    ///
    /// ## Returns
    /// A vector of 8 bytes representing the given 64-bit number.
    fn u64_to_u8_vec(number: u64) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..8 {
            result.push(((number >> (i * 8)) & 0xFF) as u8);
        }
        result.reverse();
        result
    }

    /// # Convert Message to `Vec<u64>`
    /// Convert a message represented as a slice of bytes to a vector of 64-bit integers.
    ///
    /// ## Parameters
    /// - `message`: The input message as a slice of bytes.
    ///
    /// ## Returns
    /// A vector of 64-bit integers obtained by converting chunks of 8 bytes from the input message.
    fn message_to_u64s(message: &[u8]) -> Vec<u64> {
        message.chunks(8).map(|m| key_to_u64(&to_key(m))).collect()
    }

    /// # Convert Bytes to u64
    /// Convert a slice of 8 bytes to a 64-bit integer.
    ///
    /// ## Parameters
    /// - `bytes`: The input slice of 8 bytes to be converted to a `u64`.
    ///
    /// ## Panics
    /// Panics if the input slice does not contain exactly 8 bytes.
    ///
    /// ## Returns
    /// The 64-bit integer obtained by combining the bytes in little-endian order.
    fn u64_from_bytes(bytes: &[u8]) -> u64 {
        if bytes.len() != 8 {
            panic!("Масив байтів повинен містити точно 8 байтів для конвертації в u64");
        }

        let mut result: u64 = 0;
        for i in 0..8 {
            result |= (bytes[i] as u64) << (56 - 8 * i);
        }

        result
    }

    /// Convert a slice to a `Key`.
    fn to_key(slice: &[u8]) -> Key {
        let mut vec: Vec<u8> = slice.iter().cloned().collect();
        let mut key = [0; 8];
        let diff = key.len() - vec.len();
        if diff > 0 {
            vec.append(&mut vec![0; diff]);
        }
        key.clone_from_slice(&vec);
        key
    }

    /// Convert a `u64` to a `Vec<u8>`.
    fn to_u8_vec(num: u64) -> Vec<u8> {
        vec![
            ((num & 0xFF00000000000000) >> 56) as u8,
            ((num & 0x00FF000000000000) >> 48) as u8,
            ((num & 0x0000FF0000000000) >> 40) as u8,
            ((num & 0x000000FF00000000) >> 32) as u8,
            ((num & 0x00000000FF000000) >> 24) as u8,
            ((num & 0x0000000000FF0000) >> 16) as u8,
            ((num & 0x000000000000FF00) >> 8) as u8,
            (num & 0x00000000000000FF) as u8,
        ]
    }
}

use utils::*;
