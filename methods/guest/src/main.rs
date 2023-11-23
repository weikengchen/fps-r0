//#![no_std]

extern crate alloc;
use risc0_zkvm::guest::env;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use base64ct::{Base64, Encoding};
use num_bigint::BigUint;
use core::mem::transmute;

risc0_zkvm::guest::entry!(main);

mod dkim;

mod rsa;

#[derive(Serialize, Deserialize)]
pub struct Witness {
    pub comment_line: Vec<u8>,
    pub amount: Vec<u8>,
    pub name: Vec<u8>,
    pub email: Vec<u8>,
    pub date_body: Vec<u8>,
    pub date_head: Vec<u8>,
    pub receiver: Vec<u8>,
    pub message_id: Vec<u8>,
    pub dkim_timestamp: Vec<u8>,
    pub bh_base64: Vec<u8>,
    pub receipt_number: Vec<u8>,
    pub signature_mont: Vec<u8>
}

fn check_no_rn(data: &[u8]) -> bool {
    let l = data.len();
    for i in 0..l {
        if data[i] == b'\r' || data[i] == b'\n' {
            return false;
        }
    }
    return true;
}

fn check_no_comma(data: &[u8]) -> bool {
    let l = data.len();
    for i in 0..l {
        if data[i] == b',' {
            return false;
        }
    }
    return true;
}

fn check_no_space(data: &[u8]) -> bool {
    let l = data.len();
    for i in 0..l {
        if data[i] == b' ' {
            return false;
        }
    }
    return true;
}

fn check_no_semicolon(data: &[u8]) -> bool {
    let l = data.len();
    for i in 0..l {
        if data[i] == b';' {
            return false;
        }
    }
    return true;
}

fn main() {
    let witness: Witness = env::read();

    env::commit_slice(&witness.amount);
    env::commit_slice(&witness.email);

    let mut middle_paragraph = Vec::<u8>::with_capacity(512);
    middle_paragraph.extend_from_slice(b"Your payment to send HKD ");
    middle_paragraph.extend_from_slice(&witness.amount);
    middle_paragraph.extend_from_slice(b" to ");
    middle_paragraph.extend_from_slice(&witness.name);
    middle_paragraph.extend_from_slice(b", ");
    middle_paragraph.extend_from_slice(&witness.email);
    middle_paragraph.extend_from_slice(b" via SC Pay has been transferred on ");
    middle_paragraph.extend_from_slice(&witness.date_body);
    middle_paragraph.extend_from_slice(b" successfully.");

    let mut cur = 0;
    let mut middle_paragraph_len = middle_paragraph.len();

    let mut extended_middle_paragraph = Vec::<u8>::with_capacity(512);

    while middle_paragraph_len > 74 {
        extended_middle_paragraph.extend_from_slice(&middle_paragraph[cur..cur+74]);
        extended_middle_paragraph.extend_from_slice(b"=\r\n");
        cur += 74;
        middle_paragraph_len -= 74;
    }
    if middle_paragraph_len != 0 {
        extended_middle_paragraph.extend_from_slice(&middle_paragraph[cur..cur + middle_paragraph_len]);
    }

    let mut body = Vec::<u8>::with_capacity(512);
    body.extend_from_slice(b"------=_Part_");
    body.extend_from_slice(&witness.comment_line);
    body.extend_from_slice(b"\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nDear Valued Client,\r\n\r\nThank you for using Standard Chartered Pay(\"SC Pay\") service.\r\n\r\n");
    body.extend_from_slice(&extended_middle_paragraph);
    body.extend_from_slice(b"\r\n\r\nIf you didn=E2=80=99t make this payment, please contact our Customer Servi=\r\nce Hotline at (852) 2886 8868 immediately.\r\n\r\nYours sincerely,\r\nStandard Chartered Bank (Hong Kong) Limited\r\n\r\nThis email and any attachments are confidential and may also be privileged=\r\n. If you are not the intended recipient, please delete all copies and noti=\r\nfy the sender immediately. You may wish to refer to the incorporation deta=\r\nils of Standard Chartered PLC, Standard Chartered Bank and their subsidiar=\r\nies together with Standard Chartered Bank=E2=80=99s Privacy Policy via our=\r\n public website.\r\n------=_Part_");
    body.extend_from_slice(&witness.comment_line);
    body.extend_from_slice(b"--\r\n");

    let body_hash = dkim::body_hash_sha256(&body);

    let mut header = Vec::<u8>::with_capacity(512);
    header.extend_from_slice(b"date:");
    header.extend_from_slice(&witness.date_head);
    header.extend_from_slice(b"\r\nfrom:Standard Chartered Alerts <OnlineBanking.HK@sc.com>\r\nto:");
    header.extend_from_slice(&witness.receiver);
    header.extend_from_slice(b"\r\nmessage-id:");
    header.extend_from_slice(&witness.message_id);
    header.extend_from_slice(b"\r\nsubject:=?UTF-8?Q?Send_Money_via_Standard_Chartered_?= =?UTF-8?Q?Pay_=E2=80=93_Receipt_No._");
    header.extend_from_slice(&witness.receipt_number);
    header.extend_from_slice(b"?=\r\nmime-version:1.0\r\ncontent-type:multipart/mixed; boundary=\"----=_Part_");
    header.extend_from_slice(&witness.comment_line);
    header.extend_from_slice(b"\"\r\n");

    let mut original_header = Vec::<u8>::with_capacity(512);
    original_header.extend_from_slice(b"dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=sc.com; s=k06k22gbledmsml; t=");
    original_header.extend_from_slice(&witness.dkim_timestamp);
    original_header.extend_from_slice(b"; i=@sc.com; bh=");
    original_header.extend_from_slice(&witness.bh_base64);
    original_header.extend_from_slice(b"; h=Date:From:To:Message-ID:Subject:MIME-Version:Content-Type; b=");

    let data_hash = dkim::data_hash_sha256(&header, &original_header);

    let mut dec_buf = [0u8; 32];
    let decoded = Base64::decode(&witness.bh_base64, &mut dec_buf).unwrap();
    assert_eq!(decoded, body_hash);

    let sig_mont: BigUint = BigUint::from_bytes_le(&witness.signature_mont);

    let mut sig_mont_limbs = [0u32; 64];
    sig_mont_limbs.copy_from_slice(&sig_mont.to_u32_digits());

    let mut cur_limbs = [0u32; 69];
    let mut cur2_limbs = [0u32; 69];

    // cur = ^2
    rsa::montgomery_mul(&mut cur_limbs, &sig_mont_limbs, &sig_mont_limbs);
    // cur2 = ^4
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^8
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^16
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^32
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^64
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^128
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^256
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^512
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^1024
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^2048
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^4096
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^8192
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^16384
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^32768
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
        );
    }
    // cur2 = ^65536
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
        );
    }
    // cur = ^65537
    unsafe {
        rsa::montgomery_mul(
            &mut cur_limbs,
            transmute::<&u32, &[u32;64]>(&cur2_limbs[0]),
            &sig_mont_limbs,
        );
    }

    let mut one = [0u32; 64];
    one[0] = 1;

    // cur removed montgomery
    unsafe {
        rsa::montgomery_mul(
            &mut cur2_limbs,
            transmute::<&u32, &[u32;64]>(&cur_limbs[0]),
            &one,
        );
    }

    let msg = BigUint::from_slice(&cur2_limbs[0..64]);

    assert!(check_no_rn(&witness.comment_line));
    assert!(check_no_comma(&witness.name));
    assert!(check_no_space(&witness.email));
    assert!(check_no_space(&witness.date_body));
    assert!(check_no_rn(&witness.date_head));
    assert!(check_no_rn(&witness.receiver));
    assert!(check_no_rn(&witness.message_id));
    assert!(check_no_rn(&witness.receipt_number));
    assert!(check_no_semicolon(&witness.dkim_timestamp));
    assert!(check_no_semicolon(&witness.bh_base64));

    let mut msg_bytes = [0u8; 255];
    msg_bytes[0] = 0x1;
    for i in 1..203 {
        msg_bytes[i] = 0xff;
    }
    msg_bytes[203] = 0x0;

    msg_bytes[204] = 0x30;
    msg_bytes[205] = 0x31;
    msg_bytes[206] = 0x30;
    msg_bytes[207] = 0x0d;
    msg_bytes[208] = 0x06;
    msg_bytes[209] = 0x09;
    msg_bytes[210] = 0x60;
    msg_bytes[211] = 0x86;
    msg_bytes[212] = 0x48;
    msg_bytes[213] = 0x01;
    msg_bytes[214] = 0x65;
    msg_bytes[215] = 0x03;
    msg_bytes[216] = 0x04;
    msg_bytes[217] = 0x02;
    msg_bytes[218] = 0x01;
    msg_bytes[219] = 0x05;
    msg_bytes[220] = 0x00;
    msg_bytes[221] = 0x04;
    msg_bytes[222] = 0x20;

    for i in 0..32 {
        msg_bytes[223 + i] = data_hash[i];
    }
    //env::commit_slice(&msg_bytes);

    let msg2 = BigUint::from_bytes_be(&msg_bytes);
    assert_eq!(msg, msg2);

    eprintln!("total: {}", env::get_cycle_count());
}