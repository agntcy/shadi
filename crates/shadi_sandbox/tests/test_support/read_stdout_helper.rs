use std::env;
use std::fs;
use std::io::{self, Write};

fn main() {
    let target = env::args().nth(1).expect("target path");
    let data = fs::read(target).expect("read target file");
    io::stdout().write_all(&data).expect("write stdout");
}