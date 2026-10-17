use clap::Parser;
use crate::libkagami::KagamiCommands;

mod libkagami;

fn main() {
    let command = KagamiCommands::parse();
    println!("Hello, world!");
}
