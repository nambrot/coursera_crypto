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
    let blocks_to_skip = plaintext.len() / 16;
    let bytes_to_skip = blocks_to_skip * 16;
    let padding_length = plaintext.len() - bytes_to_skip + 1;

    let mut base = cyphertext[bytes_to_skip..(bytes_to_skip + 32)].to_vec();

    set_padding_with_existing_plaintext(
        &plaintext[bytes_to_skip..],
        &mut base[16..],
        padding_length,
    );
    set_prefix_bytes(&mut base, padding_length);

    base.reverse();
    (base, padding_length as u8)
}

// fn cyphertext_for_guess(
//     cyphertext: &Vec<u8>,
//     plaintext: &Vec<u8>,
//     guess: u8,
// ) -> Result<String, String> {
//     let (mut new_cyphertext, padding_length) = get_base_cyphertext(&cyphertext, &plaintext);

//     let guess_position = new_cyphertext.len() - 16 - padding_length as usize;
//     new_cyphertext[guess_position] = new_cyphertext[guess_position] ^ guess ^ padding_length;

//     encode_hex(&new_cyphertext).map(|x| x.to_string())
// }

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

// fn construct_guess(cyphertext: &Vec<u8>, plaintext: &Vec<u8>, guess: u8) -> Result<Guess, String> {
//     let guess_cyphertext = cyphertext_for_guess(&cyphertext, &plaintext, guess)?;
//     construct_guess_request(&guess_cyphertext, guess)
// }

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
        .map_err(|_| "asd".to_string())
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

fn decode_next_byte(
    cyphertext: &Vec<u8>,
    plaintext: &Vec<u8>,
) -> impl Future<Item = u8, Error = String> {
    //  let guesses = (0..=255)
    //     .map(|guess| construct_guess(&cyphertext, &plaintext, guess))
    //     .collect::<Result<Vec<Guess>, String>>()?;
    produce_guesses(cyphertext, plaintext)
        .and_then(execute_guesses)
        .and_then(get_first_result)
}

fn decode_block(cyphertext: Vec<u8>) -> impl Future<Item = Vec<u8>, Error = String> {
    let c = cyphertext.clone();
    let x = futures::future::loop_fn(vec![], move |plaintext| {
        let p = plaintext.clone();

        if p.len() < c.len() - 16 {
            futures::future::Either::A(decode_next_byte(&cyphertext, &p).map(move |next_byte| {
                let mut new_plaintext = plaintext.clone();
                new_plaintext.push(next_byte);
                futures::future::Loop::Continue(new_plaintext)
            }))
        } else {
            futures::future::Either::B(futures::future::ok(futures::future::Loop::Break(p)))
        }
    });
    x
}

fn work(cyphertext: &Vec<u8>) -> impl Future<Item = Vec<u8>, Error = String> {
    let cyphertexts = cyphertext
        .windows(32)
        .step_by(16)
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();
    stream::iter_ok(cyphertexts)
        .map(|c| decode_block(c))
        .buffered(10)
        .collect()
        .map(|plaintexts| plaintexts.into_iter().flatten().collect())
}

pub fn attack(target_string: &str) -> Result<&str, String> {
    let mut cyphertext = decode_hex(target_string)?;
    println!("The hash to crack is {}", target_string);

    // cyphertext.truncate(cyphertext.len() - 16);
    cyphertext.reverse();

    let decode_work = work(&cyphertext);
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let plaintext = runtime.block_on(decode_work)?;
    let x = String::from_utf8(plaintext.iter().rev().map(|x| x + 0).collect()).map_err(|_| "a")?;
    let decoded_plaintext = x.trim();
    println!("Decoded plaintext is: {}", &decoded_plaintext);
    assert_eq!(
        decoded_plaintext,
        "The Magic Words are Squeamish Ossifrage".to_string()
    );

    Ok("Done")
}
