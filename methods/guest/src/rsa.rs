use core::mem::transmute;

/// RISC Zero supports BigInt operations with a width of 256-bits as 8x32-bit words.
pub(crate) const BIGINT_WIDTH_WORDS: usize = 8;
const OP_MULTIPLY: u32 = 0;

extern "C" {
    fn sys_bigint(
        result: *mut [u32; BIGINT_WIDTH_WORDS],
        op: u32,
        x: *const [u32; BIGINT_WIDTH_WORDS],
        y: *const [u32; BIGINT_WIDTH_WORDS],
        modulus: *const [u32; BIGINT_WIDTH_WORDS],
    );
}

#[inline(always)]
pub fn add_small<const I: usize, const J: usize>(accm: &mut [u32; I], new: &[u32; J]) {
    let mut carry = 0;
    (carry, accm[0]) = add32_and_overflow(accm[0], new[0], carry);
    for i in 1..J {
        (carry, accm[i]) = add32_and_overflow(accm[i], new[i], carry);
    }
    for i in J..I {
        (carry, accm[i]) = add32_and_overflow(accm[i], carry, 0);
    }
}

#[inline(always)]
pub fn add32_and_overflow(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let v = (a as u64).wrapping_add(b as u64).wrapping_add(carry as u64);
    ((v >> 32) as u32, (v & 0xffffffff) as u32)
}

#[inline(always)]
pub fn add_small_with_overflow<const I: usize, const J: usize>(accm: &mut [u32; I], new: &[u32; J]) -> u32 {
    let mut carry = 0;
    (carry, accm[0]) = add32_and_overflow(accm[0], new[0], carry);
    for i in 1..J {
        (carry, accm[i]) = add32_and_overflow(accm[i], new[i], carry);
    }
    for i in J..I{
        (carry, accm[i]) = add32_and_overflow(accm[i], carry, 0);
    }
    carry
}

pub fn montgomery_mul(out: &mut [u32; 69], in1: &[u32; 64], in2: &[u32; 64], always_reduce: bool) {
    const N: [u32; 128] = [
        3493812455u32,
        3529997461u32,
        710143587u32,
        2792692495u32,
        0u32,
        0u32,
        0u32,
        0u32,
        1885047707u32,
        3553628773u32,
        2204079629u32,
        699911535u32,
        0u32,
        0u32,
        0u32,
        0u32,
        3275286756u32,
        2670964040u32,
        380836659u32,
        1539088076u32,
        0u32,
        0u32,
        0u32,
        0u32,
        257233178u32,
        102057303u32,
        3498423094u32,
        347591143u32,
        0u32,
        0u32,
        0u32,
        0u32,
        118634769u32,
        2922120165u32,
        4044052678u32,
        3306267357u32,
        0u32,
        0u32,
        0u32,
        0u32,
        3299705609u32,
        2232715160u32,
        2567218027u32,
        57867452u32,
        0u32,
        0u32,
        0u32,
        0u32,
        3266166781u32,
        2351768864u32,
        296981719u32,
        1570354344u32,
        0u32,
        0u32,
        0u32,
        0u32,
        4098249795u32,
        2000361393u32,
        1479034620u32,
        3336008768u32,
        0u32,
        0u32,
        0u32,
        0u32,
        2938032753u32,
        3528598023u32,
        1304193507u32,
        121827407u32,
        0u32,
        0u32,
        0u32,
        0u32,
        514584826u32,
        1603753032u32,
        1664712145u32,
        3527467765u32,
        0u32,
        0u32,
        0u32,
        0u32,
        2821704060u32,
        729040642u32,
        2110748820u32,
        3709644666u32,
        0u32,
        0u32,
        0u32,
        0u32,
        4149792411u32,
        1565350608u32,
        3206857463u32,
        792901230u32,
        0u32,
        0u32,
        0u32,
        0u32,
        3569404149u32,
        1620994961u32,
        33783729u32,
        1281610576u32,
        0u32,
        0u32,
        0u32,
        0u32,
        468794176u32,
        1193160222u32,
        3636051391u32,
        2450661453u32,
        0u32,
        0u32,
        0u32,
        0u32,
        4242348214u32,
        2150858390u32,
        1813504491u32,
        305305593u32,
        0u32,
        0u32,
        0u32,
        0u32,
        1673370015u32,
        1864962247u32,
        2629885700u32,
        2947918631u32,
        0u32,
        0u32,
        0u32,
        0u32,
    ];

    const N_PRIME: [u32; 8] = [
        585614633u32,
        2908974031u32,
        1039385565u32,
        3435485210u32,
        0u32,
        0u32,
        0u32,
        0u32
    ];

    for i in 0..69 {
        out[i] = 0;
    }

    let mut res = [0u32; 8];
    let mut m = [0u32; 8];

    for i in 0..16 {
        // C := 0
        let mut carry = [0u32; 4];
        let b = [in2[i * 4], in2[i * 4 + 1], in2[i * 4 + 2], in2[i * 4 + 3], 0u32, 0, 0, 0];

        for j in 0..16 {
            let a = [in1[j * 4], in1[j * 4 + 1], in1[j * 4 + 2], in1[j * 4 + 3], 0u32, 0, 0, 0];

            // a[j] * b[i]
            unsafe {
                sys_bigint(
                    res.as_mut_ptr() as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    a.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    b.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    &[0u32; 8],
                );
            }

            // a[j] * b[i] + carry
            if j != 0 {
                add_small::<8, 4>(&mut res, &carry);
            }

            // (C,S) := t[j] + a[j]*b[i] + C
            // t[j] := S
            unsafe {
                let new_carry = add_small_with_overflow::<4, 4>(
                    transmute::<&mut u32, &mut [u32; 4]>(&mut out[j * 4]),
                    transmute::<&[u32; 8], &[u32; 4]>(&res)
                );

                // update C
                if new_carry == 0 {
                    carry[0] = res[4];
                    carry[1] = res[5];
                    carry[2] = res[6];
                    carry[3] = res[7];
                } else {
                    let (cur, mut new_carry_bit) = res[4].overflowing_add(1 as u32);
                    carry[0] = cur;
                    (carry[1], new_carry_bit) = res[5].overflowing_add(new_carry_bit as u32);
                    (carry[2], new_carry_bit) = res[6].overflowing_add(new_carry_bit as u32);
                    carry[3] = res[7].wrapping_add(new_carry_bit as u32);
                }
            }
        }

        // (C,S) := t[s] + C
        // t[s] := S
        unsafe {
            let new_carry = add_small_with_overflow::<4, 4>(
                transmute::<&mut u32, &mut [u32; 4]>(&mut out[64]),
                &carry
            );

            // t[s+1] := C
            out[68] = new_carry;
        }

        // C := 0
        let mut carry = [0u32; 4];

        // m := t[0]*n'[0] mod W
        {
            let a = [out[0], out[1], out[2], out[3], 0u32, 0, 0, 0];

            unsafe {
                sys_bigint(
                    m.as_mut_ptr() as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    a.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    N_PRIME.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    &[0u32, 0, 0, 0, 1, 0, 0, 0],
                );
            }
        }

        for j in 0..16 {
            // m * n[j]
            unsafe {
                sys_bigint(
                    res.as_mut_ptr() as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    m.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    transmute::<&u32, &[u32; 8]>(&N[j * 8]).as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    &[0u32; 8],
                );
            }

            // m * n[j] + carry
            if j != 0 {
                add_small::<8, 4>(&mut res, &carry);
            }

            // (C,S) := t[j] + m * n[j] + C
            // t[j] := S
            unsafe {
                let new_carry = add_small_with_overflow::<4, 4>(
                    transmute::<&mut u32, &mut [u32; 4]>(&mut out[j * 4]),
                    transmute::<&[u32; 8], &[u32; 4]>(&res)
                );

                // update C
                if new_carry == 0 {
                    carry[0] = res[4];
                    carry[1] = res[5];
                    carry[2] = res[6];
                    carry[3] = res[7];
                } else {
                    let (cur, mut new_carry_bit) = res[4].overflowing_add(1 as u32);
                    carry[0] = cur;
                    (carry[1], new_carry_bit) = res[5].overflowing_add(new_carry_bit as u32);
                    (carry[2], new_carry_bit) = res[6].overflowing_add(new_carry_bit as u32);
                    carry[3] = res[7].wrapping_add(new_carry_bit as u32);
                }
            }
        }

        // (C,S) := t[s] + C
        // t[s] := S
        unsafe {
            let new_carry = add_small_with_overflow::<4, 4>(
                transmute::<&mut u32, &mut [u32; 4]>(&mut out[64]),
                &carry
            );

            // t[s+1] := t[s+1] + C
            out[68] = out[68].wrapping_add(new_carry);
        }

        for j in 0..16 {
            out[j * 4] = out[j * 4 + 4];
            out[j * 4 + 1] = out[j * 4 + 4 + 1];
            out[j * 4 + 2] = out[j * 4 + 4 + 2];
            out[j * 4 + 3] = out[j * 4 + 4 + 3];
        }

        out[64] = out[68];
        out[65] = 0;
        out[66] = 0;
        out[67] = 0;
    }

    if always_reduce {
        let mut u = [0u32; 64];
        let mut borrow = 0u32;
        for i in 0..16 {
            for j in 0..4 {
                let res = ((out[i * 4 + j] as u64).wrapping_add(0x100000000)).wrapping_sub(N[i * 8 + j] as u64).wrapping_sub(borrow as u64);
                u[i * 4 + j] = (res & 0xffffffff) as u32;
                borrow = 1u32.wrapping_sub((res >> 32) as u32);
            }
        }
        let (_, borrow_bit) = out[64].overflowing_sub(borrow);
        // u[64] = cur;

        // t > n
        if borrow_bit == false {
            for i in 0..64 {
                out[i] = u[i];
            }
        }
    } else if out[64] == 1 {
        let mut borrow = 0u32;
        for i in 0..16 {
            for j in 0..4 {
                let res = ((out[i * 4 + j] as u64).wrapping_add(0x100000000)).wrapping_sub(N[i * 8 + j] as u64).wrapping_sub(borrow as u64);
                out[i * 4 + j] = (res & 0xffffffff) as u32;
                borrow = 1u32.wrapping_sub((res >> 32) as u32);
            }
        }
    }
}