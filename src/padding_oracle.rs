extern crate hyper;
extern crate tokio;
use futures::stream;
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

// fn cyphertext_for_guess_mut(
//     cyphertext: &Vec<u8>,
//     plaintext: &Vec<u8>,
//     guess: u8,
// ) -> Result<String, String> {
//     let mut index = 0;
//     let blocks_to_skip = plaintext.len() / 16;
//     let bytes_to_skip = blocks_to_skip * 16;
//     index = index + bytes_to_skip;

//     let mut new_cyphertext = cyphertext[index..(index + 32)].to_vec();

//     let padding_length = (plaintext.len() - bytes_to_skip + 1) as u8;
//     (&mut new_cyphertext[16..(15 + padding_length as usize)])
//         .iter_mut()
//         .zip(plaintext[bytes_to_skip..(bytes_to_skip + padding_length as usize - 1)].iter())
//         .for_each(|(original_byte, plaintext_byte)| *original_byte = *original_byte ^ plaintext_byte ^ padding_length);
//     new_cyphertext[15 + padding_length as usize] = new_cyphertext[15 + padding_length as usize] ^ guess ^ padding_length;
//     for prefix_byte in new_cyphertext[16 + padding_length as usize..].iter_mut() { *prefix_byte = 0 }

//     new_cyphertext.reverse();

//     encode_hex(&new_cyphertext).map(|x| x.to_string())
// }


fn cyphertext_for_guess(
    cyphertext: &Vec<u8>,
    plaintext: &Vec<u8>,
    guess: u8,
) -> Result<String, String> {
    let blocks_to_skip = plaintext.len() / 16;
    let bytes_to_skip = blocks_to_skip * 16;
    let padding_length = (plaintext.len() - bytes_to_skip + 1) as u8;

    let postfix = cyphertext
        .iter()
        .skip(blocks_to_skip * 16)
        .take(16)
        .map(|x| x + 0)
        .collect();

    let chars_to_overwrite: Vec<u8> = cyphertext
        .iter()
        .skip(blocks_to_skip * 16)
        .skip(16)
        .take(padding_length as usize - 1)
        .map(|x| x + 0)
        .collect();
    let char_to_replace = cyphertext[blocks_to_skip * 16 + 15 + padding_length as usize];
    let old_cypertext = cyphertext
        .iter()
        .skip(blocks_to_skip * 16)
        .skip((padding_length as usize) + 16)
        .take(16 - padding_length as usize)
        .map(|_x| 0)
        .collect::<Vec<u8>>();

    let mut cyphertext = [
        postfix,
        plaintext
            .iter()
            .skip(blocks_to_skip * 16)
            .zip(chars_to_overwrite.iter())
            .map(|(plain_text_char, cyphertext_char)| {
                plain_text_char ^ cyphertext_char ^ padding_length
            })
            .collect(),
        vec![char_to_replace ^ guess ^ padding_length],
        old_cypertext,
    ]
    .concat();

    cyphertext.reverse();
    encode_hex(&cyphertext).map(|x| x.to_string())
}

fn construct_guess(cyphertext: &Vec<u8>, plaintext: &Vec<u8>, guess: u8) -> Result<Guess, String> {
    let guess_cyphertext = cyphertext_for_guess(&cyphertext, &plaintext, guess)?;

    let url = ("http://crypto-class.appspot.com/po?er=".to_string() + &guess_cyphertext)
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

fn decode_next_byte(cyphertext: &Vec<u8>, plaintext: &Vec<u8>) -> Result<u8, String> {
    let client = Client::new();
    let guesses = (0..=255)
        .map(|guess| construct_guess(&cyphertext, &plaintext, guess))
        .collect::<Result<Vec<Guess>, String>>()?;

    let my_stream = stream::iter_ok(guesses)
        .map(move |guess| {
            let copied_guess = guess.guess;
            client
                .request(guess.request)
                .map(move |res| match res.status() {
                    StatusCode::NOT_FOUND => Some(copied_guess),
                    _ => None,
                })
        })
        .buffer_unordered(40);

    let work = my_stream
        .filter_map(|x| x)
        .take(1)
        .collect()
        .map_err(|e| panic!("Error making request: {}", e));

    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = runtime.block_on(work);
    result.and_then(|x| {
        x.first()
            .map(|x| x.clone())
            .ok_or("Couldn't guess byte".to_string())
    })
}

pub fn attack(target_string: &str) -> Result<&str, String> {
    let mut cyphertext = decode_hex(target_string)?;
    println!("The hash to crack is {}", target_string);

    // cyphertext.truncate(cyphertext.len() - 16);
    cyphertext.reverse();
    let mut plaintext: Vec<u8> = vec![];

    // at this point, we have both plaintext and cyphertext as reversed bytes vectors
    // call decode_next_byte repeatedly
    while plaintext.len() < cyphertext.len() - 16 {
        let next_byte = decode_next_byte(&cyphertext, &plaintext)?;
        plaintext.push(next_byte);
        println!(
            "Current plaintext: {}",
            String::from_utf8(plaintext.iter().rev().map(|x| x + 0).collect()).unwrap()
        );
    }

    assert_eq!(
        String::from_utf8(plaintext.iter().rev().map(|x| x + 0).collect())
            .unwrap()
            .trim(),
        "The Magic Words are Squeamish Ossifrage".to_string()
    );

    Ok("Done")
}
