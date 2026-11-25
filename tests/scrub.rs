//! Password hash scrubber: both hash shapes, the places they appear, truncation and the no-match cases.

use std::borrow::Cow;

use postgres_mcp::scrub::{
    REDACTED, cut_index, scrub, scrub_counting, scrub_hex_tail, scrub_value,
};
use proptest::prelude::*;
use serde_json::json;

const SCRAM: &str = "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5";
const MD5: &str = "md5d41d8cd98f00b204e9800998ecf8427e";

#[test]
fn the_replacement_text_is_exact() {
    assert_eq!(REDACTED, "[redacted password hash]");
}

#[test]
fn a_scram_verifier_and_an_md5_hash_are_replaced() {
    assert_eq!(scrub(SCRAM), REDACTED);
    assert_eq!(scrub(MD5), REDACTED);
    assert_eq!(scrub_counting(SCRAM), (Cow::Borrowed(REDACTED), 1));
}

#[test]
fn a_hash_inside_a_postgres_array_literal_is_replaced_and_the_rest_kept() {
    let text = format!("{{first,\"{SCRAM}\",last}}");
    assert_eq!(scrub(&text), "{first,\"[redacted password hash]\",last}");
}

#[test]
fn a_hash_inside_json_text_is_replaced() {
    let text = format!("{{\"rolpassword\":\"{SCRAM}\",\"n\":1}}");
    assert_eq!(
        scrub(&text),
        "{\"rolpassword\":\"[redacted password hash]\",\"n\":1}"
    );
}

#[test]
fn several_hashes_in_one_string_are_each_replaced_and_counted() {
    let text = format!("a {SCRAM} b {MD5} c {SCRAM}");
    assert_eq!(
        scrub_counting(&text),
        (
            Cow::Owned(format!("a {REDACTED} b {REDACTED} c {REDACTED}")),
            3
        )
    );
}

#[test]
fn hashes_next_to_quotes_commas_and_braces_and_at_both_ends() {
    assert_eq!(scrub(SCRAM), REDACTED);
    assert_eq!(scrub(&format!("'{SCRAM}'")), format!("'{REDACTED}'"));
    assert_eq!(scrub(&format!("{{{SCRAM}}}")), format!("{{{REDACTED}}}"));
    assert_eq!(scrub(&format!(",{MD5},")), format!(",{REDACTED},"));
    assert_eq!(scrub(&format!("x:{MD5}:y")), format!("x:{REDACTED}:y"));
}

#[test]
fn a_truncated_scram_prefix_is_replaced_up_to_the_next_other_character() {
    assert_eq!(scrub("SCRAM-SHA-256$4096:abc"), REDACTED);
    assert_eq!(
        scrub("SCRAM-SHA-256$4096:abc more"),
        format!("{REDACTED} more")
    );
    assert_eq!(scrub("SCRAM-SHA-256$"), REDACTED);
    assert_eq!(
        scrub("see SCRAM-SHA-256$4096:ab\"c\""),
        "see [redacted password hash]\"c\""
    );
}

#[test]
fn md5_with_the_wrong_digit_count_or_without_its_prefix_is_untouched() {
    let digits31 = "d41d8cd98f00b204e9800998ecf8427";
    let digits33 = "d41d8cd98f00b204e9800998ecf8427e0";
    for text in [
        format!("md5{digits31}"),
        format!("md5{digits33}"),
        digits31.to_owned() + "e",
        "d41d8cd98f00b204e9800998ecf8427e".to_owned(),
        "md5".to_owned(),
        "md5 alone".to_owned(),
        format!("xmd5{}", "d41d8cd98f00b204e9800998ecf8427e"),
    ] {
        let (out, count) = scrub_counting(&text);
        assert_eq!(count, 0, "{text}");
        assert!(matches!(out, Cow::Borrowed(_)), "{text}");
    }
}

#[test]
fn md5_hex_may_be_upper_case_and_is_bounded_by_non_alphanumerics() {
    assert_eq!(scrub("md5D41D8CD98F00B204E9800998ECF8427E"), REDACTED);
    assert_eq!(
        scrub("(md5d41d8cd98f00b204e9800998ecf8427e)"),
        format!("({REDACTED})")
    );
}

#[test]
fn multi_byte_text_around_a_match_is_kept_intact() {
    let text = format!("héllo ✓ {SCRAM} ünïcode");
    assert_eq!(scrub(&text), format!("héllo ✓ {REDACTED} ünïcode"));
}

#[test]
fn a_value_without_the_markers_is_borrowed_and_unchanged() {
    let text = "plain text with md4 and SCRAM-SHA-256 but no dollar";
    assert!(matches!(scrub(text), Cow::Borrowed(_)));
    assert_eq!(scrub(text), text);
}

#[test]
fn scrub_value_replaces_strings_keys_and_nested_values() {
    let mut value = json!({
        &format!("key {MD5}"): [SCRAM, {"inner": format!("a {MD5}")}],
        "plain": 7,
        "none": null,
    });
    let count = scrub_value(&mut value);
    assert_eq!(count, 3);
    assert_eq!(
        value,
        json!({
            format!("key {REDACTED}"): [REDACTED, {"inner": format!("a {REDACTED}")}],
            "plain": 7,
            "none": null,
        })
    );
}

proptest! {
    /// Output never holds a full match: scrubbing it again finds nothing, and text without the markers is borrowed.
    #[test]
    fn output_never_contains_a_full_match(
        before in "[ -~]{0,40}",
        after in "[ -~]{0,40}",
        digits in "[0-9]{1,4}",
        salt in "[A-Za-z0-9+/]{1,24}=*",
    ) {
        let hash = format!("SCRAM-SHA-256${digits}:{salt}$key:server");
        let text = format!("{before} {hash} {after} {MD5}");
        let (once, count) = scrub_counting(&text);
        prop_assert!(count >= 2, "{}", text);
        let twice = scrub_counting(&once);
        prop_assert_eq!(twice.1, 0, "{}", once);
        prop_assert!(!once.contains("SCRAM-SHA-256$"), "{}", once);
    }

    #[test]
    fn text_without_the_markers_is_returned_borrowed(text in "[a-zA-Z0-9 ,.:;'\"()-]{0,120}") {
        prop_assume!(!text.contains("SCRAM-SHA-256$") && !text.contains("md5"));
        prop_assert!(matches!(scrub(&text), Cow::Borrowed(_)));
    }
}

#[test]
fn an_object_without_a_hash_in_its_keys_keeps_every_key_and_count() {
    let mut value = json!({"plain": 1, "other": {"nested": "x"}});
    let count = scrub_value(&mut value);
    assert_eq!(count, 0);
    assert_eq!(value, json!({"plain": 1, "other": {"nested": "x"}}));
}

#[test]
fn a_changed_key_that_collides_with_an_unchanged_key_takes_a_numbered_name() {
    let mut value = json!({
        "a [redacted password hash]": 1,
        format!("a {MD5}"): 2,
    });
    let count = scrub_value(&mut value);
    assert_eq!(count, 1);
    assert_eq!(
        value,
        json!({
            "a [redacted password hash]": 1,
            "a [redacted password hash]__2": 2,
        })
    );
}

#[test]
fn two_changed_keys_with_the_same_replacement_name_are_both_kept() {
    let mut value = json!({
        format!("a {SCRAM}"): 1,
        format!("a {MD5}"): 2,
        format!("a {MD5} b"): 3,
    });
    let count = scrub_value(&mut value);
    assert_eq!(count, 3);
    let object = value.as_object().expect("object");
    assert_eq!(object.len(), 3, "{value}");
    let total: i64 = object.values().map(|v| v.as_i64().expect("number")).sum();
    assert_eq!(total, 6);
    for name in [
        "a [redacted password hash]",
        "a [redacted password hash]__2",
        "a [redacted password hash] b",
    ] {
        assert!(object.contains_key(name), "{name} missing in {value}");
    }
}

#[test]
fn a_third_collision_takes_the_next_number() {
    let mut value = json!({
        format!("k {SCRAM}"): 1,
        format!("k {MD5}"): 2,
        "k SCRAM-SHA-256$4096:Zg==$Zg==:Zg==".to_owned(): 3,
    });
    let count = scrub_value(&mut value);
    assert_eq!(count, 3);
    let object = value.as_object().expect("object");
    assert_eq!(object.len(), 3, "{value}");
    assert!(object.contains_key("k [redacted password hash]"), "{value}");
    assert!(
        object.contains_key("k [redacted password hash]__2"),
        "{value}"
    );
    assert!(
        object.contains_key("k [redacted password hash]__3"),
        "{value}"
    );
}

#[test]
fn an_md5_hash_followed_directly_by_a_scram_verifier_is_replaced_twice() {
    assert_eq!(
        scrub(&format!("{MD5}{SCRAM}")),
        format!("{REDACTED}{REDACTED}")
    );
}

#[test]
fn a_scram_verifier_followed_directly_by_an_md5_hash_is_replaced_once() {
    assert_eq!(scrub(&format!("{SCRAM}{MD5}")), REDACTED);
}

#[test]
fn two_md5_hashes_without_a_separator_are_both_replaced() {
    assert_eq!(
        scrub(&format!("{MD5}{MD5}")),
        format!("{REDACTED}{REDACTED}")
    );
}

/// The text that packed hashes must scrub to: a SCRAM verifier absorbs the hashes that follow it with no
/// separator; an md5 hash that comes first is replaced on its own.
fn expected_packed(pieces: &[u8]) -> String {
    let mut out = String::new();
    let mut absorbed = false;
    for &piece in pieces {
        match piece {
            2 => {
                out.push('-');
                absorbed = false;
            }
            0 => {
                if !absorbed {
                    out.push_str(REDACTED);
                    absorbed = true;
                }
            }
            _ => {
                if !absorbed {
                    out.push_str(REDACTED);
                }
            }
        }
    }
    out
}

proptest! {
    /// Hashes packed with no separator scrub to the independent expectation, and scrubbing again changes nothing.
    #[test]
    fn packed_hashes_scrub_to_the_expected_text(
        pieces in proptest::collection::vec(0_u8..3, 1..8),
        hex in "[0-9a-f]{32}",
    ) {
        let md5 = format!("md5{hex}");
        let text: String = pieces
            .iter()
            .map(|piece| match piece {
                0 => SCRAM.to_owned(),
                1 => md5.clone(),
                _ => "-".to_owned(),
            })
            .collect();
        let once = scrub(&text).into_owned();
        prop_assert_eq!(&once, &expected_packed(&pieces), "{}", text);
        prop_assert_eq!(scrub(&once).into_owned(), once.clone());
    }
}

#[test]
fn a_cut_never_leaves_part_of_a_marker_behind() {
    // The marker starts at byte 3 and ends at byte 28: a cut inside it moves to byte 3.
    let text = format!("abc{REDACTED}def");
    for max in 0..=text.len() {
        let expected = if max <= 3 {
            max
        } else if max < 3 + REDACTED.len() {
            3
        } else {
            max
        };
        assert_eq!(cut_index(text.as_bytes(), max), expected, "max {max}");
        let kept = &text[..expected];
        let partial = (1..REDACTED.len()).any(|n| kept.ends_with(&REDACTED[..n]));
        assert!(!partial, "max {max} kept {kept:?}");
    }
}

#[test]
fn a_hash_in_a_hex_escape_is_replaced_in_its_hex_form() {
    let hex_of = |text: &str| -> String { text.bytes().map(|b| format!("{b:02x}")).collect() };
    let text = format!("(\\\\x{})", hex_of(SCRAM));
    assert_eq!(scrub(&text), format!("(\\\\x{})", hex_of(REDACTED)));
}

#[test]
fn an_escape_that_holds_no_hash_is_left_alone() {
    let text = r"a\xdeadbeef b\\x00ff";
    assert_eq!(scrub(text), text);
}

fn hex_of(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn twenty_nine_thousand_adjacent_md5_hashes_scrub_in_linear_time() {
    let text = MD5.repeat(29_000);
    let started = std::time::Instant::now();
    let out = scrub(&text).into_owned();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(out, REDACTED.repeat(29_000));
}

#[test]
fn four_thousand_adjacent_md5_hashes_in_hex_form_scrub_in_linear_time() {
    let text = format!("\\x{}", hex_of(&MD5.repeat(4_000)));
    let started = std::time::Instant::now();
    let out = scrub(&text).into_owned();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(out, format!("\\x{}", hex_of(&REDACTED.repeat(4_000))));
}

/// The hex digits the scrubber does not replace keep their letter case.
#[test]
fn hex_digits_around_a_replaced_hash_keep_their_case() {
    let text = format!("\\xDEADBEEF{}CAFE", hex_of(MD5));
    assert_eq!(scrub(&text), format!("\\xDEADBEEF{}CAFE", hex_of(REDACTED)));
}

/// A value cut inside a hex run: the md5 digits the cut kept are replaced with the marker, in hex.
#[test]
fn an_md5_token_at_the_end_of_a_cut_hex_run_is_replaced() {
    let prefix = "xx ";
    let digits = &MD5[3..34];
    let kept = format!("{prefix}md5{}", &digits[..31]);
    let value = format!("row\\x{}", hex_of(&kept));
    let (out, found) = scrub_hex_tail(value.as_bytes());
    assert_eq!(found, 1);
    assert_eq!(
        String::from_utf8_lossy(&out),
        format!("row\\x{}", hex_of(&format!("{prefix}{REDACTED}")))
    );
}

/// An odd trailing hex digit after a replaced hash is dropped with the hash.
#[test]
fn an_odd_digit_after_a_cut_md5_token_is_dropped() {
    let kept = format!("xx md5{}", &MD5[3..34]);
    let value = format!("\\x{}a", hex_of(&kept));
    let (out, found) = scrub_hex_tail(value.as_bytes());
    assert_eq!(found, 1);
    assert_eq!(
        String::from_utf8_lossy(&out),
        format!("\\x{}", hex_of(&format!("xx {REDACTED}")))
    );
}

/// A cut hex run that holds no md5 token is returned unchanged.
#[test]
fn a_cut_hex_run_without_an_md5_token_is_unchanged() {
    let value = format!("row\\x{}", hex_of("hello world, no hash here"));
    let (out, found) = scrub_hex_tail(value.as_bytes());
    assert_eq!(found, 0);
    assert_eq!(out.as_ref(), value.as_bytes());
}

/// An md5 hash at the end of the text is replaced before any proper prefix of the next token.
#[test]
fn an_md5_hash_before_any_prefix_of_the_next_token_is_replaced() {
    for len in 1..=3 {
        let prefix = &"md5"[..len];
        assert_eq!(
            scrub(&format!("{MD5}{prefix}")),
            format!("{REDACTED}{prefix}")
        );
    }
    for len in 1..=13 {
        let prefix = &"SCRAM-SHA-256$"[..len];
        assert_eq!(
            scrub(&format!("{MD5}{prefix}")),
            format!("{REDACTED}{prefix}")
        );
    }
}

proptest! {
    /// A cut anywhere in packed hashes leaves no whole md5 hash that the full text replaces.
    #[test]
    fn a_cut_leaves_no_whole_md5_hash_that_the_full_text_replaces(
        pieces in proptest::collection::vec(0_u8..4, 1..8),
        hexes in proptest::collection::vec("[0-9a-f]{32}", 8),
        cut in 0_usize..400,
    ) {
        let mut text = String::new();
        let mut hashes = Vec::new();
        for (i, piece) in pieces.iter().enumerate() {
            match piece {
                0 => text.push_str(SCRAM),
                1 => {
                    let hash = format!("md5{}", hexes[i]);
                    text.push_str(&hash);
                    hashes.push(hash);
                }
                2 => text.push('-'),
                _ => text.push(' '),
            }
        }
        let cut = cut.min(text.len());
        let out = scrub(&text[..cut]).into_owned();
        for hash in &hashes {
            prop_assert!(!out.contains(hash.as_str()), "{out}");
        }
    }
}

/// A hex-form marker is never cut in half: the cut moves to the marker's first byte.
#[test]
fn a_cut_never_leaves_part_of_a_hex_form_marker_behind() {
    let text = format!("\\x{}", hex_of(REDACTED));
    for max in 0..=text.len() {
        let expected = if (3..text.len()).contains(&max) {
            2
        } else {
            max
        };
        assert_eq!(cut_index(text.as_bytes(), max), expected, "max {max}");
    }
}

/// The digits a hex tail keeps keep their letter case; the replaced hash is written in lower-case hex.
#[test]
fn scrub_hex_tail_keeps_the_case_of_the_digits_it_keeps() {
    let text = format!("\\xDEADbeef{}a", &hex_of(MD5)[..68]);
    let (out, found) = scrub_hex_tail(text.as_bytes());
    assert_eq!(found, 1);
    assert_eq!(
        String::from_utf8_lossy(&out),
        format!("\\xDEADbeef{}", hex_of(REDACTED))
    );
}

/// Ordinary hex that ends in the start of a marker's hex is not a marker: the cut stays where it was asked.
#[test]
fn an_ordinary_hex_run_ending_in_marker_hex_is_cut_where_asked() {
    assert_eq!(cut_index(b"\\xaabb5b", 7), 7);
    assert_eq!(cut_index(b"\\xaabb5b72", 9), 9);
}
