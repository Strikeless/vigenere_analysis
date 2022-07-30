#![feature(slice_partition_dedup)]

use log::{debug, info};
use std::io;
use std::io::Write;

const KASISKI_MIN_SLICE_LENGTH: usize = 2;
const KASISKI_MIN_KEY_LENGTH: usize = 4;
const KASISKI_MIN_DUPLICATES: usize = 4;

fn main() {
    pretty_env_logger::init();

    print!("Enter ciphertext: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut ciphertext = String::new();

    io::stdin()
        .read_line(&mut ciphertext)
        .expect("Failed to read line from stdin");
    ciphertext = ciphertext
        .trim()
        .to_string()
        .replace(|c: char| !c.is_ascii(), "_");

    let mut key_lengths = Vec::new();

    let ciphertext_len = ciphertext.len();

    // The maximum slice length to be tested against kasiski examination.
    // This may only be up to half of the ciphertext's length, as otherwise
    // a match is impossible due to there not being enough text for a full match.
    let max_slice_len = ciphertext_len / 2;

    // Loop over every possible slice length starting from the highest.
    for slice_len in (KASISKI_MIN_SLICE_LENGTH..=max_slice_len).rev() {
        // Get all the slices of the given length
        let slices = get_slices(&ciphertext, &slice_len);
        debug!("{} slices of length {}", slices.len(), slice_len);

        // Get an iterator of the slices
        let mut iter = slices.into_iter();

        // Loop through every slice in the iterator while consuming them.
        // The reason why we want to consume here, is that we don't need to
        // match content behind the current slice, as those have already been matched,
        // since if a=b then b=a, where a can be our slice, and b our content to be matched.
        while let Some(slice) = iter.next() {
            // Now enumerate through everything left in the iterator without consuming it
            // so that we can use these slices again in the while loop.
            // TODO: Achieve the same behaviour without cloning
            for (relative_index, other_slice) in iter.clone().enumerate() {
                if other_slice.eq(slice) {
                    debug!(
                        "Matched \"{}\" at relative index {}",
                        other_slice, relative_index
                    );

                    let mut factors = get_factors(relative_index + 1);
                    key_lengths.append(&mut factors);
                }
            }
        }
    }

    // this is a mess

    key_lengths.sort();
    let (key_lengths, key_length_dupes) = key_lengths.partition_dedup();

    key_lengths.sort_by_key(|key_len| {
        key_length_dupes
            .iter()
            .filter(|dupe| *dupe == key_len)
            .count()
    });
    key_lengths.reverse();

    info!("Examined key lengths:");
    for key_len in key_lengths {
        let occurrences = key_length_dupes
            .iter()
            .filter(|dupe| *dupe == key_len)
            .count();

        if *key_len < KASISKI_MIN_KEY_LENGTH || occurrences < KASISKI_MIN_DUPLICATES {
            continue;
        }

        info!("  {}: {}", key_len, occurrences);
    }
}

fn get_slices<'a>(text: &'a str, len: &usize) -> Vec<&'a str> {
    let items = text.len() - len + 1;
    let mut vec = Vec::with_capacity(items);

    for i in 0..items {
        vec.push(&text[i..i + len]);
    }

    vec
}

fn get_factors(value: usize) -> Vec<usize> {
    // a nice functional solution i found somewhere
    (1..=value)
        .into_iter()
        .filter(|&x| value % x == 0)
        .collect()
}
