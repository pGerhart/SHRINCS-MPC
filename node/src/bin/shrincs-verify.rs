//! `shrincs-verify <pk> <msg> <sig> [ctx]`, all hex.

#![forbid(unsafe_code)]

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if !(3..=4).contains(&a.len()) {
        eprintln!("usage: shrincs-verify <pk> <msg> <sig> [ctx], all hex");
        std::process::exit(2);
    }
    let h = |i: usize| {
        hex::decode(a.get(i).map_or("", String::as_str)).unwrap_or_else(|_| {
            eprintln!("argument {} is not hex", i + 1);
            std::process::exit(2)
        })
    };
    match shrincs::verify_bytes(&h(1), &h(2), &h(3), &h(0)) {
        Ok(()) => println!("valid"),
        Err(e) => {
            println!("INVALID: {e}");
            std::process::exit(1);
        }
    }
}
