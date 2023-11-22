//#![no_std]

extern crate alloc;
use risc0_zkvm::guest::env;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use base64ct::{Base64, Encoding};
use num_bigint_dig::BigUint;

risc0_zkvm::guest::entry!(main);

mod dkim;

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
    pub signature: Vec<u8>
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
    let n = BigUint::from_slice(&N_ELEMS);
    let sig: BigUint = BigUint::from_bytes_be(&witness.signature);

    eprintln!("before modpow: {}", env::get_cycle_count());
    let msg = BigUint::modpow(&sig, &BigUint::from(65537u32), &n);
    eprintln!("after modpow: {}", env::get_cycle_count());

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