#![warn(clippy::pedantic, clippy::nursery)]

use daence::ChaChaDaence;
use std::time::Instant;

fn main() {
    let key =
        "FV/ZV91vER+hhyf5xAVFQgtSFkZ9BcBISJnCTIzD7ZncoCaDVkZXEWJ9rhRGDVqh0phEpNC7H6AGHaE2q/F1zw==";
    let key = &base64::decode(key).unwrap().try_into().unwrap();

    // what can I do if I don't have any ¯\_(ツ)_/¯
    let additional_data = &[];

    // Cloneable, reusable, stateless. For now...
    let daence = ChaChaDaence::new(key, additional_data);

    let pb = |x: &[u8]| {
        println!();
        x.iter().for_each(|x| print!("{x:08b} "));
    };
    let ph = |x: &[u8]| {
        println!();
        x.iter().for_each(|x| print!("{x:02x} "));
    };
    let do_it = |pn: fn(&[u8]), x: &[u8]| {
        let x = &mut x.to_vec();
        let t = &mut [0; 24];
        pn(x);
        print!("{} bytes", x.len());
        let start = Instant::now();

        daence.encrypt(x, t);
        pn(x);
        pn(t);
        print!("= {} bytes for total {} bytes ", t.len(), x.len() + t.len());

        print!("{:?}", Instant::now() - start);

        pn(x);

        if daence.decrypt(x, t).is_err() {
            eprintln!("forgery");
        }

        pn(x);
        println!("{:?}", Instant::now() - start);
    };
    do_it(pb, "Bepis! 🐴".as_bytes());
    do_it(pb, "Bepjs! 🐴".as_bytes());
    do_it(ph, &[0; 32]);
    {
        let mut buf = [0; 24];
        let u128 = <&mut [_; 16]>::try_from(&mut buf[0..16]).unwrap();
        *u128 = rand::random::<u128>().to_le_bytes();
        let i64 = <&mut [_; 8]>::try_from(&mut buf[16..16 + 8]).unwrap();
        *i64 = rand::random::<i64>().to_le_bytes();
        do_it(ph, &buf);
    }
}
