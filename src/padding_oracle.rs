extern crate hyper;
extern crate tokio;
use futures::stream;
use hyper::client::HttpConnector;
use hyper::rt::{Future, Stream};
use hyper::{Body, Client, Request, StatusCode, Uri};

fn decode_hex(string: &str) -> Result<Vec<u8>, &str> {
    string
        .chars()
        .map(|character| character.to_digit(16))
        .map(|digit| match digit {
            Some(x) if x < 16 => Some(x as u8),
            _ => None,
        })
        .collect::<Vec<Option<u8>>>()
        .chunks(2)
        .map(|double_byte| match double_byte {
            [Some(first_char), Some(second_char)] => Ok(first_char * 16 + second_char),
            _ => Err("Could not decode string"),
        })
        .collect()
}

fn encode_hex(bytes: &Vec<u8>) -> Result<String, String> {
    let x = bytes
        .iter()
        .map(|digit| {
            match (
                std::char::from_digit((digit / 16) as u32, 16),
                std::char::from_digit((digit % 16) as u32, 16),
            ) {
                (Some(x), Some(y)) => Ok(vec![x, y]),
                _ => Err("Could not convert digit"),
            }
        })
        .collect::<Result<Vec<Vec<char>>, &str>>()?
        .iter()
        .flatten()
        .collect::<String>();
    Ok(x.clone())
}
#[derive(Debug)]
struct Guess {
    guess: u8,
    request: Request<Body>,
}

// Sets the bytes in the block after the guess position to the padding length
fn set_padding_with_existing_plaintext(plaintext: &[u8], base: &mut [u8], padding_length: usize) {
    let end = padding_length - 1;
    base[0..end]
        .iter_mut()
        .zip(plaintext[0..end].iter())
        .for_each(|(original_byte, plaintext_byte)| {
            *original_byte = *original_byte ^ plaintext_byte ^ padding_length as u8
        });
}

// Set the preceding bytes to the guess to reduce the chance of accidentally
// having a "wrong" guess result in a correct padding, especially for the original last block
fn set_prefix_bytes(base: &mut [u8], padding_length: usize) {
    for prefix_byte in base[(16 + padding_length)..].iter_mut() {
        *prefix_byte = 0
    }
}

// 1 arg is the cyphertext without the guess flip, the second argument is the padding length
fn get_base_cyphertext(cyphertext: &Vec<u8>, plaintext: &Vec<u8>) -> (Vec<u8>, u8) {
    let padding_length = plaintext.len() + 1;

    let mut base = cyphertext.clone();

    set_padding_with_existing_plaintext(&plaintext[0..], &mut base[16..], padding_length);
    set_prefix_bytes(&mut base, padding_length);

    base.reverse();
    (base, padding_length as u8)
}

fn construct_guess_request(cyphertext: &str, guess: u8) -> Result<Guess, String> {
    let url = ("http://crypto-class.appspot.com/po?er=".to_string() + cyphertext)
        .parse::<Uri>()
        .map_err(|_| "Couldn't produce url for guess".to_string())?;

    let request = Request::get(url)
        .body(Body::empty())
        .map_err(|_| "Couldn't produce request".to_string())?;

    Ok(Guess {
        guess: guess,
        request: request,
    })
}

fn construct_guess_from_base(
    base: &mut Vec<u8>,
    padding_length: u8,
    guess: u8,
) -> Result<Guess, String> {
    let guess_position = base.len() - 16 - padding_length as usize;
    // Flip the guess byte
    base[guess_position] = base[guess_position] ^ guess ^ padding_length;
    let cyphertext = encode_hex(&base)?;
    let guess_request = construct_guess_request(&cyphertext, guess)?;
    // Flip the guess byte back
    base[guess_position] = base[guess_position] ^ guess ^ padding_length;
    Ok(guess_request)
}

fn create_request(
    guess: Guess,
    client: &Client<HttpConnector>,
) -> impl Future<Item = Option<u8>, Error = String> {
    let copied_guess = guess.guess;
    client
        .request(guess.request)
        .map(move |res| match res.status() {
            StatusCode::NOT_FOUND => Some(copied_guess),
            _ => None,
        })
        .map_err(|_| "Request failed".to_string())
}

fn produce_guesses(
    cyphertext: &Vec<u8>,
    plaintext: &Vec<u8>,
) -> impl Future<Item = Vec<Guess>, Error = String> {
    let (mut base_cyphertext, padding_length) = get_base_cyphertext(&cyphertext, &plaintext);

    let guesses = (0..=255)
        .map(|guess| construct_guess_from_base(&mut base_cyphertext, padding_length, guess))
        .collect::<Result<Vec<Guess>, String>>();

    futures::future::result(guesses)
}

fn execute_guesses(guesses: Vec<Guess>) -> impl Future<Item = Vec<u8>, Error = String> {
    let client = Client::new();

    stream::iter_ok(guesses)
        .map(move |guess| create_request(guess, &client))
        .buffer_unordered(40)
        .filter_map(|x| x)
        .take(1)
        .collect()
        .map_err(|e| panic!("Error making request: {}", e))
}

fn get_first_result<T: Clone>(vector: Vec<T>) -> impl Future<Item = T, Error = String> {
    let result = vector
        .first()
        .cloned()
        .ok_or("Couldn't get byte".to_string());
    futures::future::result(result)
}

fn decode_block(cyphertext: Vec<u8>) -> impl Future<Item = Vec<u8>, Error = String> {
    futures::stream::iter_ok(0..16).fold(vec![], move |plaintext, _index| {
        produce_guesses(&cyphertext, &plaintext)
            .and_then(execute_guesses)
            .and_then(get_first_result)
            .map(move |next_byte| {
                let mut new_plaintext = plaintext.clone();
                new_plaintext.push(next_byte);
                new_plaintext
            })
    })
}

fn work(cyphertext: &Vec<u8>) -> impl Future<Item = Vec<u8>, Error = String> {
    let cyphertext_blocks = cyphertext
        .windows(32)
        .step_by(16)
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();
    stream::iter_ok(cyphertext_blocks)
        .map(|c| decode_block(c))
        .buffered(10)
        .collect()
        .map(|plaintexts| plaintexts.into_iter().flatten().collect())
}

pub fn attack(target_string: &str) -> Result<String, String> {
    let mut cyphertext = decode_hex(target_string)?;
    println!("The cyphertext to crack is {}", target_string);

    cyphertext.reverse();

    let decode_work = work(&cyphertext);
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let plaintext = runtime.block_on(decode_work)?;

    String::from_utf8(plaintext.iter().rev().map(|x| x + 0).collect())
        .map_err(|_| "Couldn't decode result".to_string())
        .map(|x| x.trim().to_string())
}
