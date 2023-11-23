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
pub fn add_small_with_overflow<const I: usize, const J: usize>(
    accm: &mut [u32; I],
    new: &[u32; J],
) -> u32 {
    let mut carry = 0;
    (carry, accm[0]) = add32_and_overflow(accm[0], new[0], carry);
    for i in 1..J {
        (carry, accm[i]) = add32_and_overflow(accm[i], new[i], carry);
    }
    for i in J..I {
        (carry, accm[i]) = add32_and_overflow(accm[i], carry, 0);
    }
    carry
}

#[inline(always)]
pub fn sub_with_borrow(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let res = ((a as u64).wrapping_add(0x100000000))
        .wrapping_sub(b as u64)
        .wrapping_sub(carry as u64);
    (
        (res & 0xffffffff) as u32,
        1u32.wrapping_sub((res >> 32) as u32),
    )
}

#[inline(always)]
pub fn sub_and_borrow<const I: usize>(accu: &mut [u32; I], new: &[u32; I]) -> u32 {
    let (cur, borrow) = accu[0].overflowing_sub(new[0]);
    accu[0] = cur;

    let mut borrow = borrow as u32;
    for i in 1..I - 1 {
        (accu[i], borrow) = sub_with_borrow(accu[i], new[i], borrow);
    }
    (accu[I - 1], borrow) = sub_with_borrow(accu[I - 1], new[I - 1], borrow);
    borrow
}

pub fn montgomery_mul(out: &mut [u32; 73], in1: &[u32; 64], in2: &[u32; 64], always_reduce: bool) {
    const N: [u32; 64] = [
        3493812455u32,
        3529997461u32,
        710143587u32,
        2792692495u32,
        1885047707u32,
        3553628773u32,
        2204079629u32,
        699911535u32,
        3275286756u32,
        2670964040u32,
        380836659u32,
        1539088076u32,
        257233178u32,
        102057303u32,
        3498423094u32,
        347591143u32,
        118634769u32,
        2922120165u32,
        4044052678u32,
        3306267357u32,
        3299705609u32,
        2232715160u32,
        2567218027u32,
        57867452u32,
        3266166781u32,
        2351768864u32,
        296981719u32,
        1570354344u32,
        4098249795u32,
        2000361393u32,
        1479034620u32,
        3336008768u32,
        2938032753u32,
        3528598023u32,
        1304193507u32,
        121827407u32,
        514584826u32,
        1603753032u32,
        1664712145u32,
        3527467765u32,
        2821704060u32,
        729040642u32,
        2110748820u32,
        3709644666u32,
        4149792411u32,
        1565350608u32,
        3206857463u32,
        792901230u32,
        3569404149u32,
        1620994961u32,
        33783729u32,
        1281610576u32,
        468794176u32,
        1193160222u32,
        3636051391u32,
        2450661453u32,
        4242348214u32,
        2150858390u32,
        1813504491u32,
        305305593u32,
        1673370015u32,
        1864962247u32,
        2629885700u32,
        2947918631u32,
    ];

    const N_PRIME: [u32; 8] = [
        585614633u32,
        2908974031u32,
        1039385565u32,
        3435485210u32,
        4058094229u32,
        358995547u32,
        248098438u32,
        1590364234u32,
    ];

    for i in 0..73 {
        out[i] = 0;
    }

    let mut res = [0u32; 16];
    let mut m = [0u32; 16];

    for i in 0..8 {
        // C := 0
        let mut carry = [0u32; 8];

        for j in 0..8 {
            // a[j] * b[i]
            unsafe {
                sys_bigint(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[0])
                        as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    transmute::<&u32, &[u32; 8]>(&in1[j * 8]) as *const [u32; BIGINT_WIDTH_WORDS],
                    transmute::<&u32, &[u32; 8]>(&in2[i * 8]) as *const [u32; BIGINT_WIDTH_WORDS],
                    &[0xffffffffu32; 8],
                );
            }

            unsafe {
                sys_bigint(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[8])
                        as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    transmute::<&u32, &[u32; 8]>(&in1[j * 8]) as *const [u32; BIGINT_WIDTH_WORDS],
                    transmute::<&u32, &[u32; 8]>(&in2[i * 8]) as *const [u32; BIGINT_WIDTH_WORDS],
                    &[
                        0xfffffffeu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                    ],
                );
            }

            unsafe {
                let borrow = sub_and_borrow::<8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[8]),
                    transmute::<&u32, &[u32; 8]>(&res[0]),
                );

                if borrow != 0 {
                    let (cur, mut new_borrow_bit) = res[8].overflowing_sub(2 as u32);
                    res[8] = cur;
                    (res[9], new_borrow_bit) = res[9].overflowing_sub(new_borrow_bit as u32);
                    (res[10], new_borrow_bit) = res[10].overflowing_sub(new_borrow_bit as u32);
                    (res[11], new_borrow_bit) = res[11].overflowing_sub(new_borrow_bit as u32);
                    (res[12], new_borrow_bit) = res[12].overflowing_sub(new_borrow_bit as u32);
                    (res[13], new_borrow_bit) = res[13].overflowing_sub(new_borrow_bit as u32);
                    (res[14], new_borrow_bit) = res[14].overflowing_sub(new_borrow_bit as u32);
                    res[15] = res[15].wrapping_sub(new_borrow_bit as u32);
                }
            }

            unsafe {
                let borrow = sub_and_borrow::<8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[0]),
                    transmute::<&u32, &[u32; 8]>(&res[8]),
                );
                if borrow != 0 {
                    let (cur, mut new_borrow_bit) = res[8].overflowing_sub(1 as u32);
                    res[8] = cur;
                    (res[9], new_borrow_bit) = res[9].overflowing_sub(new_borrow_bit as u32);
                    (res[10], new_borrow_bit) = res[10].overflowing_sub(new_borrow_bit as u32);
                    (res[11], new_borrow_bit) = res[11].overflowing_sub(new_borrow_bit as u32);
                    (res[12], new_borrow_bit) = res[12].overflowing_sub(new_borrow_bit as u32);
                    (res[13], new_borrow_bit) = res[13].overflowing_sub(new_borrow_bit as u32);
                    (res[14], new_borrow_bit) = res[14].overflowing_sub(new_borrow_bit as u32);
                    res[15] = res[15].wrapping_sub(new_borrow_bit as u32);
                }
            }

            // a[j] * b[i] + carry
            if j != 0 {
                add_small::<16, 8>(&mut res, &carry);
            }

            // (C,S) := t[j] + a[j]*b[i] + C
            // t[j] := S
            unsafe {
                let new_carry = add_small_with_overflow::<8, 8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut out[j * 8]),
                    transmute::<&u32, &[u32; 8]>(&res[0]),
                );

                // update C
                if new_carry == 0 {
                    carry[0] = res[8];
                    carry[1] = res[9];
                    carry[2] = res[10];
                    carry[3] = res[11];
                    carry[4] = res[12];
                    carry[5] = res[13];
                    carry[6] = res[14];
                    carry[7] = res[15];
                } else {
                    let (cur, mut new_carry_bit) = res[8].overflowing_add(new_carry as u32);
                    carry[0] = cur;
                    (carry[1], new_carry_bit) = res[9].overflowing_add(new_carry_bit as u32);
                    (carry[2], new_carry_bit) = res[10].overflowing_add(new_carry_bit as u32);
                    (carry[3], new_carry_bit) = res[11].overflowing_add(new_carry_bit as u32);
                    (carry[4], new_carry_bit) = res[12].overflowing_add(new_carry_bit as u32);
                    (carry[5], new_carry_bit) = res[13].overflowing_add(new_carry_bit as u32);
                    (carry[6], new_carry_bit) = res[14].overflowing_add(new_carry_bit as u32);
                    carry[7] = res[15].wrapping_add(new_carry_bit as u32);
                }
            }
        }

        // (C,S) := t[s] + C
        // t[s] := S
        unsafe {
            let new_carry = add_small_with_overflow::<8, 8>(
                transmute::<&mut u32, &mut [u32; 8]>(&mut out[64]),
                &carry,
            );

            // t[s+1] := C
            out[72] = new_carry;
        }

        // C := 0
        let mut carry = [0u32; 8];

        // m := t[0]*n'[0] mod W
        {
            unsafe {
                sys_bigint(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut m[0])
                        as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    transmute::<&u32, &[u32; 8]>(&out[0]).as_ptr()
                        as *const [u32; BIGINT_WIDTH_WORDS],
                    N_PRIME.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    &[0xffffffffu32; 8],
                );
            }

            unsafe {
                sys_bigint(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut m[8])
                        as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    transmute::<&u32, &[u32; 8]>(&out[0]).as_ptr()
                        as *const [u32; BIGINT_WIDTH_WORDS],
                    N_PRIME.as_ptr() as *const [u32; BIGINT_WIDTH_WORDS],
                    &[
                        0xfffffffeu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                    ],
                );
            }

            unsafe {
                let borrow = sub_and_borrow::<8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut m[8]),
                    transmute::<&u32, &[u32; 8]>(&m[0]),
                );
                if borrow != 0 {
                    let (cur, mut new_borrow_bit) = m[8].overflowing_sub(2 as u32);
                    m[8] = cur;
                    (m[9], new_borrow_bit) = m[9].overflowing_sub(new_borrow_bit as u32);
                    (m[10], new_borrow_bit) = m[10].overflowing_sub(new_borrow_bit as u32);
                    (m[11], new_borrow_bit) = m[11].overflowing_sub(new_borrow_bit as u32);
                    (m[12], new_borrow_bit) = m[12].overflowing_sub(new_borrow_bit as u32);
                    (m[13], new_borrow_bit) = m[13].overflowing_sub(new_borrow_bit as u32);
                    (m[14], new_borrow_bit) = m[14].overflowing_sub(new_borrow_bit as u32);
                    m[15] = m[15].wrapping_sub(new_borrow_bit as u32);
                }
            }

            unsafe {
                let borrow = sub_and_borrow::<8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut m[0]),
                    transmute::<&u32, &[u32; 8]>(&m[8]),
                );
                if borrow != 0 {
                    let (cur, mut new_borrow_bit) = m[8].overflowing_sub(1 as u32);
                    m[8] = cur;
                    (m[9], new_borrow_bit) = m[9].overflowing_sub(new_borrow_bit as u32);
                    (m[10], new_borrow_bit) = m[10].overflowing_sub(new_borrow_bit as u32);
                    (m[11], new_borrow_bit) = m[11].overflowing_sub(new_borrow_bit as u32);
                    (m[12], new_borrow_bit) = m[12].overflowing_sub(new_borrow_bit as u32);
                    (m[13], new_borrow_bit) = m[13].overflowing_sub(new_borrow_bit as u32);
                    (m[14], new_borrow_bit) = m[14].overflowing_sub(new_borrow_bit as u32);
                    m[15] = m[15].wrapping_sub(new_borrow_bit as u32);
                }
            }
        }

        for j in 0..8 {
            // m * n[j]
            unsafe {
                sys_bigint(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[0])
                        as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    transmute::<&mut u32, &mut [u32; 8]>(&mut m[0])
                        as *const [u32; BIGINT_WIDTH_WORDS],
                    transmute::<&u32, &[u32; 8]>(&N[j * 8]) as *const [u32; BIGINT_WIDTH_WORDS],
                    &[0xffffffffu32; 8],
                );
            }

            unsafe {
                sys_bigint(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[8])
                        as *mut [u32; BIGINT_WIDTH_WORDS],
                    OP_MULTIPLY,
                    transmute::<&mut u32, &mut [u32; 8]>(&mut m[0])
                        as *const [u32; BIGINT_WIDTH_WORDS],
                    transmute::<&u32, &[u32; 8]>(&N[j * 8]) as *const [u32; BIGINT_WIDTH_WORDS],
                    &[
                        0xfffffffeu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                        0xffffffffu32,
                    ],
                );
            }

            unsafe {
                let borrow = sub_and_borrow::<8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[8]),
                    transmute::<&u32, &[u32; 8]>(&res[0]),
                );
                if borrow != 0 {
                    let (cur, mut new_borrow_bit) = res[8].overflowing_sub(2 as u32);
                    res[8] = cur;
                    (res[9], new_borrow_bit) = res[9].overflowing_sub(new_borrow_bit as u32);
                    (res[10], new_borrow_bit) = res[10].overflowing_sub(new_borrow_bit as u32);
                    (res[11], new_borrow_bit) = res[11].overflowing_sub(new_borrow_bit as u32);
                    (res[12], new_borrow_bit) = res[12].overflowing_sub(new_borrow_bit as u32);
                    (res[13], new_borrow_bit) = res[13].overflowing_sub(new_borrow_bit as u32);
                    (res[14], new_borrow_bit) = res[14].overflowing_sub(new_borrow_bit as u32);
                    res[15] = res[15].wrapping_sub(new_borrow_bit as u32);
                }
            }

            unsafe {
                let borrow = sub_and_borrow::<8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut res[0]),
                    transmute::<&u32, &[u32; 8]>(&res[8]),
                );
                if borrow != 0 {
                    let (cur, mut new_borrow_bit) = res[8].overflowing_sub(1 as u32);
                    res[8] = cur;
                    (res[9], new_borrow_bit) = res[9].overflowing_sub(new_borrow_bit as u32);
                    (res[10], new_borrow_bit) = res[10].overflowing_sub(new_borrow_bit as u32);
                    (res[11], new_borrow_bit) = res[11].overflowing_sub(new_borrow_bit as u32);
                    (res[12], new_borrow_bit) = res[12].overflowing_sub(new_borrow_bit as u32);
                    (res[13], new_borrow_bit) = res[13].overflowing_sub(new_borrow_bit as u32);
                    (res[14], new_borrow_bit) = res[14].overflowing_sub(new_borrow_bit as u32);
                    res[15] = res[15].wrapping_sub(new_borrow_bit as u32);
                }
            }

            // m * n[j] + carry
            if j != 0 {
                add_small::<16, 8>(&mut res, &carry);
            }

            // (C,S) := t[j] + m * n[j] + C
            // t[j] := S
            unsafe {
                let new_carry = add_small_with_overflow::<8, 8>(
                    transmute::<&mut u32, &mut [u32; 8]>(&mut out[j * 8]),
                    transmute::<&[u32; 16], &[u32; 8]>(&res),
                );

                // update C
                if new_carry == 0 {
                    carry[0] = res[8];
                    carry[1] = res[9];
                    carry[2] = res[10];
                    carry[3] = res[11];
                    carry[4] = res[12];
                    carry[5] = res[13];
                    carry[6] = res[14];
                    carry[7] = res[15];
                } else {
                    let (cur, mut new_carry_bit) = res[8].overflowing_add(1 as u32);
                    carry[0] = cur;
                    (carry[1], new_carry_bit) = res[9].overflowing_add(new_carry_bit as u32);
                    (carry[2], new_carry_bit) = res[10].overflowing_add(new_carry_bit as u32);
                    (carry[3], new_carry_bit) = res[11].overflowing_add(new_carry_bit as u32);
                    (carry[4], new_carry_bit) = res[12].overflowing_add(new_carry_bit as u32);
                    (carry[5], new_carry_bit) = res[13].overflowing_add(new_carry_bit as u32);
                    (carry[6], new_carry_bit) = res[14].overflowing_add(new_carry_bit as u32);
                    carry[7] = res[15].wrapping_add(new_carry_bit as u32);
                }
            }
        }

        // (C,S) := t[s] + C
        // t[s] := S
        unsafe {
            let new_carry = add_small_with_overflow::<8, 8>(
                transmute::<&mut u32, &mut [u32; 8]>(&mut out[64]),
                &carry,
            );

            // t[s+1] := t[s+1] + C
            out[72] = out[72].wrapping_add(new_carry);
        }

        for j in 0..8 {
            out[j * 8] = out[j * 8 + 8];
            out[j * 8 + 1] = out[j * 8 + 8 + 1];
            out[j * 8 + 2] = out[j * 8 + 8 + 2];
            out[j * 8 + 3] = out[j * 8 + 8 + 3];
            out[j * 8 + 4] = out[j * 8 + 8 + 4];
            out[j * 8 + 5] = out[j * 8 + 8 + 5];
            out[j * 8 + 6] = out[j * 8 + 8 + 6];
            out[j * 8 + 7] = out[j * 8 + 8 + 7];
        }

        out[64] = out[72];
        out[65] = 0;
        out[66] = 0;
        out[67] = 0;
        out[68] = 0;
        out[69] = 0;
        out[70] = 0;
        out[71] = 0;
    }

    if always_reduce {
        let mut u = [0u32; 64];
        let mut borrow = 0u32;
        for i in 0..64 {
            let res = ((out[i] as u64).wrapping_add(0x100000000))
                .wrapping_sub(N[i] as u64)
                .wrapping_sub(borrow as u64);
            u[i] = (res & 0xffffffff) as u32;
            borrow = 1u32.wrapping_sub((res >> 32) as u32);
        }
        let (_, borrow_bit) = out[64].overflowing_sub(borrow);

        // t > n
        if borrow_bit == false {
            for i in 0..64 {
                out[i] = u[i];
            }
        }
    } else if out[64] == 1 {
        let mut borrow = 0u32;
        for i in 0..64 {
            let res = ((out[i] as u64).wrapping_add(0x100000000))
                .wrapping_sub(N[i] as u64)
                .wrapping_sub(borrow as u64);
            out[i] = (res & 0xffffffff) as u32;
            borrow = 1u32.wrapping_sub((res >> 32) as u32);
        }
    }
}
