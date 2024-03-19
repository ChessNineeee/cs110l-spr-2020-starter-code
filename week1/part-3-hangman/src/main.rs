// Simple Hangman Program
// User gets five incorrect guesses
// Word chosen randomly from words.txt
// Inspiration from: https://doc.rust-lang.org/book/ch02-00-guessing-game-tutorial.html
// This assignment will introduce you to some fundamental syntax in Rust:
// - variable declaration
// - string manipulation
// - conditional statements
// - loops
// - vectors
// - files
// - user input
// We've tried to limit/hide Rust's quirks since we'll discuss those details
// more in depth in the coming lectures.
extern crate rand;
use rand::Rng;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::Write;

const NUM_INCORRECT_GUESSES: u32 = 5;
const WORDS_PATH: &str = "words.txt";

fn pick_a_random_word() -> String {
    let file_string = fs::read_to_string(WORDS_PATH).expect("Unable to read file.");
    let words: Vec<&str> = file_string.split('\n').collect();
    String::from(words[rand::thread_rng().gen_range(0, words.len())].trim())
}

fn main() {
    let secret_word = pick_a_random_word();
    // Note: given what you know about Rust so far, it's easier to pull characters out of a
    // vector than it is to pull them out of a string. You can get the ith character of
    // secret_word by doing secret_word_chars[i].
    let mut secret_word_chars: Vec<char> = secret_word.chars().collect();
    // Uncomment for debugging:
    println!("random word: {}", secret_word);

    // Your code here! :)
    println!("Welcome to CS110L Hangman!");

    let mut counter = 5;
    let mut guessed = String::new();
    let mut hit_count = 0;
    let mut so_far: Vec<char> = vec!['-'; secret_word_chars.len()];
    while counter > 0 && hit_count < secret_word_chars.len() {
        let so_far_str: String = so_far.iter().collect();
        println!("The word so far is {}", so_far_str);
        println!("You have guessed the following letters: {}", guessed);
        println!("You have {} guesses left", counter);
        print!("Please guess a letter: ");

        // Make sure the prompt from the previous line gets displayed:
        io::stdout().flush().expect("Error flushing stdout.");
        let mut guess = String::new();
        io::stdin()
            .read_line(&mut guess)
            .expect("Error reading line.");
        assert_eq!(guess.len(), 2, "should only input 1 char, quit");

        // verify
        let guess_char = guess.chars().nth(0).unwrap();
        if let Some(index) = secret_word_chars.iter().position(|&c| c == guess_char) {
            *secret_word_chars.get_mut(index).unwrap() = '*';
            *so_far.get_mut(index).unwrap() = guess_char;
            hit_count += 1;
        } else {
            println!("Sorry, that letter is not in the word");
            counter -= 1;
        }
        assert!(
            hit_count >= 0 && hit_count <= secret_word_chars.len(),
            "never fail"
        );
        guessed.push(guess_char);
    }
    if hit_count < secret_word_chars.len() {
        println!("Sorry, you ran out of guesses!");
    } else {
        println!(
            "Congratulations you guessed the secret word: {}!",
            secret_word
        );
    }
}
