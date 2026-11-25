//! Password hash scrubber: both hash shapes, the places they appear, truncation and the no-match cases.

use std::borrow::Cow;

use postgres_mcp::scrub::{REDACTED, scrub, scrub_counting, scrub_value};
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
