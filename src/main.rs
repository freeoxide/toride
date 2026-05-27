
use clap::{Parser, Subcommand};

#[tokio::main]
async fn main() -> () {
    init_tracing();
    println!("Hello world");
    ()
}
