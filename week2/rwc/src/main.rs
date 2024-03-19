use std::env;
use std::fs::File;
use std::io::{self, BufRead}; // For read_file_lines()
use std::process;

fn read_file_lines(filename: &String) -> Result<Vec<String>, io::Error> {
    // Be sure to delete the #[allow(unused)] line above
    let file = File::open(filename)?;
    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines() {
        lines.push(line?);
    }
    return Ok(lines);
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Too few arguments.");
        process::exit(1);
    }
    let filename = &args[1];
    // Your code here :)
    let lines = read_file_lines(&filename).unwrap();

    let mut word = 0;
    let line = lines.len();
    let mut char = 0;

    for it in lines.iter() {
        char += it.len();
        let splitted: Vec<&str> = it.split_whitespace().collect();
        word += splitted.len();
    }
    char += lines.len();

    println!("{} {} {} {}", line, word, char, filename);
}
