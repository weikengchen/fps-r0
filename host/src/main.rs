use serde::{Serialize, Deserialize};
use num_bigint_dig::BigUint;
use core::str::FromStr;
use methods::{METHOD_ELF, METHOD_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

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

fn main() {
    let comment_line = b"2772651_343290592.1700310140503";
    let amount = b"10.00";
    let name = b"CHEN W******";
    let email = b"w********@chenweikeng.com";
    let date_body = b"18/11/2023";
    let date_head = b"Sat, 18 Nov 2023 20:22:20 +0800";
    let receiver = b"\"WEIKENG@CHENWEIKENG.COM\" <WEIKENG@CHENWEIKENG.COM>";
    let message_id = b"<101958940.2772652.1700310140503.JavaMail.1000830000@hk-boa-15-5f8fl>";
    let dkim_timestamp = b"1700310181";
    let bh_base64 = b"hJ/+UNkf1BHOUMaYhrzDzD3adraujFmKjZajNWOLYT4=";
    let receipt_number = b"2311-182022218700";
    let signature = BigUint::from_str("10625512586255484529905913055518690041367016184139603208541053043067627026596170923852906588557400770118440711602759466843726969481836140444332240137316710742516639602143210812428949677883618101389359047511373992985514651735606880700898915238753116119729027152984350103669187052930077764847488756122702904657364560056547986875486100784117240746834017001781152776378161718685359034677365279732516706989700441393316707925352884322083934071736978776879652906169104284627863089773539963210536556881828553404441522346601372075574798832939215784948057194166388978217945842562118998420736255452138960283685002443406516028414").unwrap().to_bytes_be();

    let witness = Witness {
        comment_line: comment_line.to_vec(),
        amount: amount.to_vec(),
        name: name.to_vec(),
        email: email.to_vec(),
        date_body: date_body.to_vec(),
        date_head: date_head.to_vec(),
        receiver: receiver.to_vec(),
        message_id: message_id.to_vec(),
        dkim_timestamp: dkim_timestamp.to_vec(),
        bh_base64: bh_base64.to_vec(),
        receipt_number: receipt_number.to_vec(),
        signature,
    };

    let env = ExecutorEnv::builder()
        .write(&witness)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let timer = std::time::Instant::now();
    let receipt = prover.prove_elf(env, METHOD_ELF).unwrap();
    println!("time: {}", timer.elapsed().as_secs_f64());
    receipt.verify(METHOD_ID).unwrap();
}