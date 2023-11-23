pub fn montgomery_mul(out: &mut [u32; 66], in1: &[u32; 64], in2: &[u32; 64]) {
    const N_ELEMS: [u32; 64] = [
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

    for i in 0..66 {
        out[i] = 0;
    }
    for i in 0..64 {
        let mut carry = 0u32;
        let mut new_carry: bool;
        for j in 0..64 {
            let tmp = (in1[i] as u64).wrapping_mul(in2[j] as u64).wrapping_add(carry as u64);
            let lo = (tmp & 0xffffffff) as u32;
            carry = (tmp >> 32) as u32;

            (out[j], new_carry) = out[j].overflowing_add(lo);
            carry = carry.wrapping_add(new_carry as u32);
        }
        (out[64], new_carry) = out[64].overflowing_add(carry);
        out[65] = new_carry as u32;

        carry = 0;
        let m = out[0].wrapping_mul(585614633u32);
        for j in 0..64 {
            let tmp = (m as u64).wrapping_mul(N_ELEMS[j] as u64).wrapping_add(carry as u64);
            let lo = (tmp & 0xffffffff) as u32;
            carry = (tmp >> 32) as u32;

            (out[j], new_carry) = out[j].overflowing_add(lo);
            carry = carry.wrapping_add(new_carry as u32);
        }
        (out[64], new_carry) = out[64].overflowing_add(carry);
        out[65] = out[65].wrapping_add(new_carry as u32);

        for j in 0..=64 {
            out[j] = out[j + 1];
        }
    }

    let mut u = [0u32; 64];

    let mut borrow = 0u32;
    for i in 0..64 {
        let res = ((out[i] as u64).wrapping_add(0x100000000)).wrapping_sub(N_ELEMS[i] as u64).wrapping_sub(borrow as u64);
        u[i] = (res & 0xffffffff) as u32;
        borrow = 1u32.wrapping_sub((res >> 32) as u32);
    }
    let (_, borrow_bit) = out[64].overflowing_sub(borrow);
    //u[64] = cur;

    // t > n
    if borrow_bit == false {
        for i in 0..64 {
            out[i] = u[i];
        }
    }
}