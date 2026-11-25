use postgres_mcp::encode::{
    EncodeLimits, EncodeStats, TypeInfo, TypeKind, builtin_type, dedup_columns, encode_value,
};
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use serde_json::{Value, json};

const LIM: EncodeLimits = EncodeLimits {
    max_value_bytes: 1024,
    max_binary_preview_bytes: 16,
};

const BIG: EncodeLimits = EncodeLimits {
    max_value_bytes: 1 << 20,
    max_binary_preview_bytes: 64,
};

fn ty(oid: u32) -> TypeInfo {
    match builtin_type(oid) {
        Some(t) => t,
        None => panic!("builtin_type({oid}) is None"),
    }
}

fn enc_with(oid: u32, raw: &str, lim: &EncodeLimits) -> (Value, EncodeStats) {
    let mut st = EncodeStats::default();
    let v = encode_value(raw.as_bytes(), raw.len(), &ty(oid), lim, &mut st);
    (v, st)
}

fn enc(oid: u32, raw: &str) -> (Value, EncodeStats) {
    enc_with(oid, raw, &LIM)
}

fn stats(truncated_values: u64, raw_fallbacks: u64) -> EncodeStats {
    EncodeStats {
        truncated_values,
        raw_fallbacks,
        redacted_hashes: 0,
    }
}

#[test]
fn builtin_type_spot_checks() {
    let int4 = ty(23);
    assert_eq!(int4.name, "int4");
    assert_eq!(int4.kind, TypeKind::Int);

    let arr = ty(1007);
    assert_eq!(arr.name, "int4[]");
    assert_eq!(
        arr.kind,
        TypeKind::Array {
            elem: Box::new(int4.clone()),
            delim: ','
        }
    );

    match ty(1020).kind {
        TypeKind::Array { elem, delim } => {
            assert_eq!(delim, ';');
            assert_eq!(elem.oid, 603);
            assert_eq!(elem.kind, TypeKind::Text);
        }
        other => panic!("1020 is {other:?}"),
    }

    let r = ty(3904);
    assert_eq!(r.name, "int4range");
    assert_eq!(
        r.kind,
        TypeKind::Range {
            sub: Box::new(int4.clone())
        }
    );

    let m = ty(4451);
    assert_eq!(m.name, "int4multirange");
    assert_eq!(
        m.kind,
        TypeKind::Multirange {
            sub: Box::new(int4)
        }
    );

    let ra = ty(3905);
    assert_eq!(ra.name, "int4range[]");
    assert_eq!(
        ra.kind,
        TypeKind::Array {
            elem: Box::new(r),
            delim: ','
        }
    );

    assert_eq!(ty(25).kind, TypeKind::Text);
    assert_eq!(ty(16).kind, TypeKind::Bool);
    assert_eq!(ty(114).kind, TypeKind::Json);
    assert_eq!(ty(17).kind, TypeKind::Bytea);
    assert!(builtin_type(999999).is_none());
}

#[test]
fn builtin_type_table_entries() {
    let text_oids = [
        18, 19, 25, 1042, 1043, 2950, 142, 1082, 1083, 1114, 1184, 1266, 1186, 790, 1560, 1562,
        869, 650, 829, 774, 600, 601, 602, 603, 604, 628, 718, 3614, 3615, 4072, 3220, 5038, 2970,
        2205, 2206, 24, 2202, 2203, 2204, 3734, 3769, 4089, 4096, 4191, 22, 30, 2249, 705, 2278,
    ];
    for oid in text_oids {
        assert_eq!(ty(oid).kind, TypeKind::Text, "oid {oid}");
    }
    let bigints = [(20, "int8"), (5069, "xid8"), (6437, "oid8")];
    for (oid, name) in bigints {
        assert_eq!(ty(oid).kind, TypeKind::BigInt, "oid {oid}");
        assert_eq!(ty(oid).name, name);
    }
    assert_eq!(ty(1700).kind, TypeKind::Numeric);
    assert_eq!(ty(700).kind, TypeKind::Float);
    assert_eq!(ty(701).kind, TypeKind::Float);
    assert_eq!(ty(3802).kind, TypeKind::Json);
    assert_eq!(ty(21).kind, TypeKind::Int);
    assert_eq!(ty(26).kind, TypeKind::Int);
    assert_eq!(ty(28).kind, TypeKind::Int);
    assert_eq!(ty(29).kind, TypeKind::Int);
    assert_eq!(ty(1700).name, "numeric");
}

#[test]
fn bool_vectors() {
    assert_eq!(enc(16, "t"), (json!(true), stats(0, 0)));
    assert_eq!(enc(16, "f"), (json!(false), stats(0, 0)));
    assert_eq!(enc(16, "tx"), (json!("tx"), stats(0, 1)));
    assert_eq!(enc(16, ""), (json!(""), stats(0, 1)));
}

#[test]
fn int_vectors() {
    assert_eq!(enc(23, "42"), (json!(42), stats(0, 0)));
    assert_eq!(enc(23, "-7"), (json!(-7), stats(0, 0)));
    assert_eq!(enc(23, "0"), (json!(0), stats(0, 0)));
    assert_eq!(enc(21, "-32768"), (json!(-32768), stats(0, 0)));
    assert_eq!(enc(26, "4294967295"), (json!(4294967295u64), stats(0, 0)));
    assert_eq!(enc(23, "12a"), (json!("12a"), stats(0, 1)));
    assert_eq!(enc(23, ""), (json!(""), stats(0, 1)));
}

#[test]
fn bigint_vectors() {
    let (v, st) = enc(20, "9007199254740991");
    assert_eq!(serde_json::to_string(&v).unwrap(), "9007199254740991");
    assert_eq!(st, stats(0, 0));

    let (v, _) = enc(20, "-9007199254740991");
    assert_eq!(serde_json::to_string(&v).unwrap(), "-9007199254740991");

    assert_eq!(
        enc(20, "9007199254740992"),
        (json!("9007199254740992"), stats(0, 0))
    );
    assert_eq!(
        enc(20, "-9007199254740992"),
        (json!("-9007199254740992"), stats(0, 0))
    );
    assert_eq!(
        enc(20, "-9223372036854775808"),
        (json!("-9223372036854775808"), stats(0, 0))
    );
    assert_eq!(
        enc(6437, "18446744073709551615"),
        (json!("18446744073709551615"), stats(0, 0))
    );
    assert_eq!(
        enc(5069, "18446744073709551615"),
        (json!("18446744073709551615"), stats(0, 0))
    );
    assert_eq!(enc(20, "0"), (json!(0), stats(0, 0)));
    assert_eq!(enc(20, "x1"), (json!("x1"), stats(0, 1)));
}

#[test]
fn float_vectors() {
    let (v, st) = enc(701, "0.1");
    assert_eq!(serde_json::to_string(&v).unwrap(), "0.1");
    assert_eq!(st, stats(0, 0));

    let (v, _) = enc(701, "1e+300");
    assert_eq!(serde_json::to_string(&v).unwrap(), "1e+300");

    // Printed "-0" keeps its digits; it equals -0.0 numerically.
    let (v, st) = enc(701, "-0");
    assert_eq!(serde_json::to_string(&v).unwrap(), "-0");
    let f = v.as_f64().unwrap_or(1.0);
    assert!(f == 0.0 && f.is_sign_negative());
    assert_eq!(st, stats(0, 0));

    let (v, _) = enc(700, "3");
    assert_eq!(v.as_f64(), Some(3.0));

    assert_eq!(enc(701, "NaN"), (json!("NaN"), stats(0, 0)));
    assert_eq!(enc(701, "Infinity"), (json!("Infinity"), stats(0, 0)));
    assert_eq!(enc(700, "-Infinity"), (json!("-Infinity"), stats(0, 0)));
    assert_eq!(enc(701, "abc"), (json!("abc"), stats(0, 1)));
    assert_eq!(enc(701, "inf"), (json!("inf"), stats(0, 1)));
}

#[test]
fn numeric_vectors() {
    assert_eq!(enc(1700, "1.50"), (json!("1.50"), stats(0, 0)));
    assert_eq!(
        enc(1700, "0.00000000000000000001"),
        (json!("0.00000000000000000001"), stats(0, 0))
    );
    assert_eq!(enc(1700, "NaN"), (json!("NaN"), stats(0, 0)));
    assert_eq!(enc(1700, "Infinity"), (json!("Infinity"), stats(0, 0)));
    assert_eq!(enc(1700, "-Infinity"), (json!("-Infinity"), stats(0, 0)));
    assert_eq!(enc(1700, "0"), (json!("0"), stats(0, 0)));
}

#[test]
fn json_vectors() {
    let (v, st) = enc(3802, r#"{"a": 2, "b": 12345678901234567890.123456789}"#);
    assert_eq!(
        serde_json::to_string(&v).unwrap(),
        r#"{"a":2,"b":12345678901234567890.123456789}"#
    );
    assert_eq!(st, stats(0, 0));

    assert_eq!(enc(114, r#""x""#), (json!("x"), stats(0, 0)));
    assert_eq!(enc(114, "null"), (Value::Null, stats(0, 0)));
    assert_eq!(enc(114, "12"), (json!(12), stats(0, 0)));
    assert_eq!(enc(114, "false"), (json!(false), stats(0, 0)));
    assert_eq!(enc(114, "0"), (json!(0), stats(0, 0)));
    assert_eq!(
        enc(114, r#"{"a":[1,{"b":"x,y"}],"c":{"d":"a\"b"}}"#),
        (
            json!({"a": [1, {"b": "x,y"}], "c": {"d": "a\"b"}}),
            stats(0, 0)
        )
    );
}

#[test]
fn json_duplicate_keys_fall_back() {
    assert_eq!(
        enc(114, r#"{"a":1,"a":2}"#),
        (json!(r#"{"a":1,"a":2}"#), stats(0, 1))
    );
    assert_eq!(
        enc(3802, r#"{"x":{"k":1,"k":2}}"#),
        (json!(r#"{"x":{"k":1,"k":2}}"#), stats(0, 1))
    );
    assert_eq!(
        enc(114, r#"[{"a":1,"a":2}]"#),
        (json!(r#"[{"a":1,"a":2}]"#), stats(0, 1))
    );
    assert_eq!(
        enc(114, r#"{"a":1,"a":2}"#),
        (json!(r#"{"a":1,"a":2}"#), stats(0, 1))
    );
}

#[test]
fn json_malformed_falls_back() {
    assert_eq!(enc(114, "{bad json"), (json!("{bad json"), stats(0, 1)));
}

#[test]
fn json_over_cap_is_text_with_marker() {
    let lim = EncodeLimits {
        max_value_bytes: 10,
        max_binary_preview_bytes: 16,
    };
    let raw = r#"{"a": 1, "b": 2}"#;
    let (v, st) = enc_with(114, raw, &lim);
    assert_eq!(
        v,
        json!(format!(
            "{}…[truncated: 10 of {} bytes]",
            &raw[..10],
            raw.len()
        ))
    );
    assert_eq!(st, stats(1, 0));
}

#[test]
fn bytea_vectors() {
    assert_eq!(enc(17, r"\xdeadbeef"), (json!(r"\xdeadbeef"), stats(0, 0)));
    assert_eq!(enc(17, r"\x"), (json!(r"\x"), stats(0, 0)));
    assert_eq!(enc(17, "deadbeef"), (json!("deadbeef"), stats(0, 1)));
    assert_eq!(enc(17, r"\xabc"), (json!(r"\xabc"), stats(0, 1)));
}

#[test]
fn bytea_preview_cap() {
    let lim = EncodeLimits {
        max_value_bytes: 1024,
        max_binary_preview_bytes: 2,
    };
    // Exactly at the cap: no truncation.
    assert_eq!(
        enc_with(17, r"\xdead", &lim),
        (json!(r"\xdead"), stats(0, 0))
    );
    // Four decoded bytes over a cap of two: two bytes shown.
    assert_eq!(
        enc_with(17, r"\xdeadbeef", &lim),
        (json!("\\xdead…[truncated: 2 of 4 bytes]"), stats(1, 0))
    );
}

#[test]
fn text_vectors_round_trip() {
    let cases = [
        (1114, "infinity"),
        (1082, "0044-03-15 BC"),
        (1184, "2024-02-29 07:30:00.123456+00"),
        (1186, "P1Y2M3DT4H5M6.789S"),
        (790, "$12.34"),
        (2249, r#"(1,"x, ""y""")"#),
        (25, r#""a"=>"1", "b"=>NULL"#),
        (718, "<(0,0),1>"),
        (25, "'a' 'cat' 'fat'"),
        (869, "192.168.1.5/24"),
    ];
    for (oid, raw) in cases {
        assert_eq!(enc(oid, raw), (json!(raw), stats(0, 0)), "oid {oid}");
    }
    assert_eq!(enc(25, ""), (json!(""), stats(0, 0)));
    assert_eq!(enc(25, "0"), (json!("0"), stats(0, 0)));
}

#[test]
fn text_cap_cuts_on_char_boundary() {
    let lim = EncodeLimits {
        max_value_bytes: 10,
        max_binary_preview_bytes: 16,
    };
    assert_eq!(
        enc_with(25, "abcdefghijklmnop", &lim),
        (json!("abcdefghij…[truncated: 10 of 16 bytes]"), stats(1, 0))
    );
    // "é" is two bytes; a cap of 5 cuts back to 4.
    assert_eq!(
        enc_with(
            25,
            "ééééé",
            &EncodeLimits {
                max_value_bytes: 5,
                ..lim
            }
        ),
        (json!("éé…[truncated: 4 of 10 bytes]"), stats(1, 0))
    );
    // Exactly at the cap: unchanged.
    assert_eq!(
        enc_with(25, "abcdefghij", &lim),
        (json!("abcdefghij"), stats(0, 0))
    );
}

#[test]
fn truncated_on_wire_marker_g1() {
    let mut st = EncodeStats::default();
    let v = encode_value(b"12", 5, &ty(23), &LIM, &mut st);
    assert_eq!(v, json!("12…[truncated: 2 of 5 bytes]"));
    assert_eq!(st, stats(1, 0));

    let mut st = EncodeStats::default();
    let v = encode_value(b"abc", 10, &ty(25), &LIM, &mut st);
    assert_eq!(v, json!("abc…[truncated: 3 of 10 bytes]"));
    assert_eq!(st, stats(1, 0));

    // "a" followed by the first byte of "é": the partial char is dropped.
    let mut st = EncodeStats::default();
    let v = encode_value(&[0x61, 0xC3], 5, &ty(25), &LIM, &mut st);
    assert_eq!(v, json!("a…[truncated: 1 of 5 bytes]"));
    assert_eq!(st, stats(1, 0));

    let mut st = EncodeStats::default();
    let v = encode_value(&[0xC3], 4, &ty(25), &LIM, &mut st);
    assert_eq!(v, json!("…[truncated: 0 of 4 bytes]"));
    assert_eq!(st, stats(1, 0));
}

#[test]
fn invalid_utf8_is_hex_g2() {
    let mut st = EncodeStats::default();
    let v = encode_value(&[0x80, 0xff], 2, &ty(25), &LIM, &mut st);
    assert_eq!(v, json!("\\x80ff"));
    assert_eq!(st, stats(0, 1));

    let mut st = EncodeStats::default();
    let v = encode_value(&[0xff], 1, &ty(23), &LIM, &mut st);
    assert_eq!(v, json!("\\xff"));
    assert_eq!(st, stats(0, 1));

    let lim = EncodeLimits {
        max_value_bytes: 1024,
        max_binary_preview_bytes: 2,
    };
    let mut st = EncodeStats::default();
    let v = encode_value(&[0xff, 0x01, 0x02], 3, &ty(25), &lim, &mut st);
    assert_eq!(v, json!("\\xff01…[truncated: 2 of 3 bytes]"));
    assert_eq!(st, stats(1, 1));
}

#[test]
fn array_int_vectors() {
    assert_eq!(enc(1007, "{1,2,3}"), (json!([1, 2, 3]), stats(0, 0)));
    assert_eq!(
        enc(1007, "{{1,NULL},{3,4}}"),
        (json!([[1, null], [3, 4]]), stats(0, 0))
    );
    assert_eq!(
        enc(1007, "[2:3][0:1]={{1,NULL},{3,4}}"),
        (
            json!({"lowerBounds": [2, 0], "elements": [[1, null], [3, 4]]}),
            stats(0, 0)
        )
    );
    assert_eq!(enc(1007, "{}"), (json!([]), stats(0, 0)));
    assert_eq!(enc(1007, "{null,Null}"), (json!([null, null]), stats(0, 0)));
    assert_eq!(enc(1007, "{ 1 , 2 }"), (json!([1, 2]), stats(0, 0)));
    assert_eq!(enc(1007, "{1,1}"), (json!([1, 1]), stats(0, 0)));
    assert_eq!(enc(1007, "{1,a}"), (json!([1, "a"]), stats(0, 1)));
}

#[test]
fn array_text_vectors() {
    assert_eq!(
        enc(1009, r#"{"a b","NULL",NULL,"c\"d","e\\f",""}"#),
        (
            json!(["a b", "NULL", null, "c\"d", "e\\f", ""]),
            stats(0, 0)
        )
    );
    assert_eq!(
        enc(1009, "{{x,y},{z,w}}"),
        (json!([["x", "y"], ["z", "w"]]), stats(0, 0))
    );
}

#[test]
fn array_other_element_vectors() {
    assert_eq!(
        enc(1231, "{1.50,NaN}"),
        (json!(["1.50", "NaN"]), stats(0, 0))
    );
    assert_eq!(
        enc(3807, r#"{"{\"a\": 1}","[1, 2]"}"#),
        (json!([{"a": 1}, [1, 2]]), stats(0, 0))
    );
    assert_eq!(
        enc(1020, "{(1,1),(0,0);(3,3),(2,2)}"),
        (json!(["(1,1),(0,0)", "(3,3),(2,2)"]), stats(0, 0))
    );
    assert_eq!(
        enc(3905, r#"{"[1,5)",empty}"#),
        (
            json!([
                {"lower": 1, "upper": 5, "lowerInc": true, "upperInc": false},
                {"empty": true}
            ]),
            stats(0, 0)
        )
    );
}

#[test]
fn array_malformed_falls_back() {
    for raw in [
        "{1,2",
        "{1,}",
        "{,}",
        "{1,,2}",
        "{1}}",
        "{1}x",
        "{{1,2},{3,4}",
    ] {
        assert_eq!(enc(1007, raw), (json!(raw), stats(0, 1)), "raw {raw}");
    }
}

#[test]
fn array_over_cap_is_text_with_marker() {
    let lim = EncodeLimits {
        max_value_bytes: 2,
        max_binary_preview_bytes: 16,
    };
    let raw = "{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20}";
    assert!(raw.len() > 2 * 16);
    assert_eq!(
        enc_with(1007, raw, &lim),
        (
            json!(format!(
                "{}…[truncated: 2 of {} bytes]",
                &raw[..2],
                raw.len()
            )),
            stats(1, 0)
        )
    );
}

#[test]
fn array_large_input() {
    let items: Vec<String> = (1..=5000).map(|i| i.to_string()).collect();
    let raw = format!("{{{}}}", items.join(","));
    let expected: Vec<Value> = (1..=5000).map(|i| json!(i)).collect();
    assert_eq!(enc_with(1007, &raw, &BIG), (json!(expected), stats(0, 0)));
}

#[test]
fn array_deep_nesting_does_not_recurse() {
    let depth = 2000;
    let raw = format!("{}1{}", "{".repeat(depth), "}".repeat(depth));
    let mut expected = json!(1);
    for _ in 0..depth {
        expected = Value::Array(vec![expected]);
    }
    assert_eq!(enc_with(1007, &raw, &BIG), (expected, stats(0, 0)));
}

#[test]
fn range_vectors() {
    assert_eq!(
        enc(3904, "[1,5)"),
        (
            json!({"lower": 1, "upper": 5, "lowerInc": true, "upperInc": false}),
            stats(0, 0)
        )
    );
    assert_eq!(
        enc(3912, "(,2024-01-02)"),
        (
            json!({"lower": null, "upper": "2024-01-02", "lowerInc": false, "upperInc": false}),
            stats(0, 0)
        )
    );
    assert_eq!(
        enc(
            3910,
            r#"["2024-01-01 00:00:00+00","2024-01-02 00:00:00+00")"#
        ),
        (
            json!({
                "lower": "2024-01-01 00:00:00+00",
                "upper": "2024-01-02 00:00:00+00",
                "lowerInc": true,
                "upperInc": false
            }),
            stats(0, 0)
        )
    );
    // "]" on an unbounded upper keeps upperInc true.
    assert_eq!(
        enc(3906, "[1.5,]"),
        (
            json!({"lower": "1.5", "upper": null, "lowerInc": true, "upperInc": true}),
            stats(0, 0)
        )
    );
    assert_eq!(
        enc(3904, "(,)"),
        (
            json!({"lower": null, "upper": null, "lowerInc": false, "upperInc": false}),
            stats(0, 0)
        )
    );
    assert_eq!(enc(3904, "empty"), (json!({"empty": true}), stats(0, 0)));
}

#[test]
fn range_quoted_bounds_unescape() {
    let text_range = TypeInfo {
        oid: 0,
        name: "textrange".to_string(),
        kind: TypeKind::Range {
            sub: Box::new(ty(25)),
        },
    };
    let raw = r#"["a""b","c\\d")"#;
    let mut st = EncodeStats::default();
    let v = encode_value(raw.as_bytes(), raw.len(), &text_range, &LIM, &mut st);
    assert_eq!(
        v,
        json!({"lower": "a\"b", "upper": "c\\d", "lowerInc": true, "upperInc": false})
    );
    assert_eq!(st, stats(0, 0));
}

#[test]
fn range_malformed_falls_back() {
    for raw in ["[1,5", "[1 5)", "[1,5,6)", "x", "[1,5]x", "[1,5)x"] {
        assert_eq!(enc(3904, raw), (json!(raw), stats(0, 1)), "raw {raw}");
    }
    assert_eq!(
        enc(3904, "[1,5]"),
        (
            json!({"lower": 1, "upper": 5, "lowerInc": true, "upperInc": true}),
            stats(0, 0)
        )
    );
}

#[test]
fn multirange_vectors() {
    assert_eq!(enc(4451, "{}"), (json!([]), stats(0, 0)));
    assert_eq!(
        enc(4451, "{[1,3),[5,8)}"),
        (
            json!([
                {"lower": 1, "upper": 3, "lowerInc": true, "upperInc": false},
                {"lower": 5, "upper": 8, "lowerInc": true, "upperInc": false}
            ]),
            stats(0, 0)
        )
    );
}

#[test]
fn multirange_quoted_comma_and_malformed() {
    let text_mr = TypeInfo {
        oid: 0,
        name: "textmultirange".to_string(),
        kind: TypeKind::Multirange {
            sub: Box::new(ty(25)),
        },
    };
    let raw = r#"{["a,b",c)}"#;
    let mut st = EncodeStats::default();
    let v = encode_value(raw.as_bytes(), raw.len(), &text_mr, &LIM, &mut st);
    assert_eq!(
        v,
        json!([{"lower": "a,b", "upper": "c", "lowerInc": true, "upperInc": false}])
    );
    assert_eq!(st, stats(0, 0));

    assert_eq!(enc(4451, "{[1,3)"), (json!("{[1,3)"), stats(0, 1)));
}

#[test]
fn dedup_vectors() {
    let names = |xs: &[&str]| -> Vec<String> { xs.iter().map(|s| s.to_string()).collect() };
    let pair = |f: &str, o: Option<&str>| (f.to_string(), o.map(|s| s.to_string()));

    assert_eq!(
        dedup_columns(&names(&["id", "id", "name"])),
        vec![
            pair("id", None),
            pair("id__2", Some("id")),
            pair("name", None)
        ]
    );
    assert_eq!(
        dedup_columns(&names(&["a", "a__2", "a"])),
        vec![pair("a", None), pair("a__2", None), pair("a__3", Some("a"))]
    );
    assert_eq!(
        dedup_columns(&names(&["", "x"])),
        vec![pair("column_1", Some("")), pair("x", None)]
    );
    assert_eq!(
        dedup_columns(&names(&["?column?", "?column?"])),
        vec![
            pair("?column?", None),
            pair("?column?__2", Some("?column?"))
        ]
    );
    assert_eq!(dedup_columns(&[]), Vec::<(String, Option<String>)>::new());
    assert_eq!(
        dedup_columns(&names(&["", ""])),
        vec![pair("column_1", Some("")), pair("column_2", Some(""))]
    );
    assert_eq!(
        dedup_columns(&names(&["id", "id", "id", "id__2"])),
        vec![
            pair("id", None),
            pair("id__3", Some("id")),
            pair("id__4", Some("id")),
            pair("id__2", None)
        ]
    );
}

fn oid_pool() -> Vec<u32> {
    vec![
        16, 21, 23, 26, 20, 5069, 700, 701, 1700, 114, 3802, 17, 25, 1043, 2950, 1186, 1000, 1007,
        1009, 1020, 3904, 3905, 4451, 3908, 1231, 1001, 1184, 3807, 1115, 3910,
    ]
}

proptest! {
    #[test]
    fn encode_never_panics_on_arbitrary_bytes(
        bytes in vec(any::<u8>(), 0..300),
        idx in 0usize..31,
        extra in 0usize..4,
    ) {
        let pool = oid_pool();
        let t = ty(pool[idx % pool.len()]);
        let mut st = EncodeStats::default();
        let v = encode_value(&bytes, bytes.len() + extra, &t, &LIM, &mut st);
        prop_assert!(t.oid == 114 || t.oid == 3802 || !v.is_null());
    }

    #[test]
    fn encode_never_panics_on_structural_text(
        raw in "[\\[\\]\\(\\)\\{\\}\",;:=A-Za-z0-9 \\\\\\n-]{0,80}",
        idx in 0usize..31,
    ) {
        let pool = oid_pool();
        let t = ty(pool[idx % pool.len()]);
        let mut st = EncodeStats::default();
        let v = encode_value(raw.as_bytes(), raw.len(), &t, &LIM, &mut st);
        prop_assert!(t.oid == 114 || t.oid == 3802 || !v.is_null());
    }

    #[test]
    fn array_round_trip_text_elements(
        (dims, cells) in vec(1usize..=3, 1..=3).prop_flat_map(|dims| {
            let total: usize = dims.iter().product();
            (Just(dims), vec(option::of("(?s).{0,6}"), total))
        }),
    ) {
        let raw = render_array(&dims, &cells);
        let expected = expected_array(&dims, &cells);
        let mut st = EncodeStats::default();
        let v = encode_value(raw.as_bytes(), raw.len(), &ty(1009), &BIG, &mut st);
        prop_assert_eq!(v, expected);
        prop_assert_eq!(st, EncodeStats::default());
    }
}

fn quote_elem(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn render_array(dims: &[usize], cells: &[Option<String>]) -> String {
    if dims.len() == 1 {
        let parts: Vec<String> = cells
            .iter()
            .map(|c| match c {
                Some(s) => quote_elem(s),
                None => "NULL".to_string(),
            })
            .collect();
        return format!("{{{}}}", parts.join(","));
    }
    let stride: usize = dims[1..].iter().product();
    let parts: Vec<String> = (0..dims[0])
        .map(|k| render_array(&dims[1..], &cells[k * stride..(k + 1) * stride]))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn expected_array(dims: &[usize], cells: &[Option<String>]) -> Value {
    if dims.len() == 1 {
        return Value::Array(
            cells
                .iter()
                .map(|c| match c {
                    Some(s) => json!(s),
                    None => Value::Null,
                })
                .collect(),
        );
    }
    let stride: usize = dims[1..].iter().product();
    Value::Array(
        (0..dims[0])
            .map(|k| expected_array(&dims[1..], &cells[k * stride..(k + 1) * stride]))
            .collect(),
    )
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(text: &str) -> String {
    let digits = text.strip_prefix("\\x").expect("bytea text");
    let bytes: Vec<u8> = (0..digits.len() / 2)
        .map(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8(bytes).expect("utf8")
}

#[test]
fn a_complete_bytea_cell_holding_a_hash_shows_the_marker_as_hex() {
    let scram = "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5";
    let raw = format!("\\x{}", hex_of(scram.as_bytes()));
    let mut st = EncodeStats::default();
    let v = encode_value(raw.as_bytes(), raw.len(), &ty(17), &BIG, &mut st);
    let expected = format!("\\x{}", hex_of(b"[redacted password hash]"));
    assert_eq!(v, json!(expected));
    assert_eq!(
        decode_hex(v.as_str().expect("text")),
        "[redacted password hash]"
    );
    assert_eq!(st.redacted_hashes, 1);
}

#[test]
fn an_md5_hash_straddling_the_wire_cut_of_a_bytea_cell_is_replaced_in_its_bytes() {
    let md5 = "md5d41d8cd98f00b204e9800998ecf8427e";
    let full: Vec<u8> = [b"xxxx ".as_slice(), md5.as_bytes()].concat();
    let full_text = format!("\\x{}", hex_of(&full));
    // The value is 40 bytes; the wire keeps 36 bytes of its 82-byte hex text: "\x", then 17 bytes of xxxx, a space, md5 and nine digits.
    let kept = &full_text[..36];
    let mut st = EncodeStats::default();
    let v = encode_value(kept.as_bytes(), full_text.len(), &ty(17), &LIM, &mut st);
    let text = v.as_str().expect("text");
    let (shown, marker) = text.split_once('…').expect("truncation marker");
    assert_eq!(marker, "[truncated: 29 of 40 bytes]");
    assert_eq!(decode_hex(shown), "xxxx [redacted password hash]");
    assert!(!decode_hex(shown).contains("md5"), "{text}");
    assert_eq!(st.redacted_hashes, 1);
    assert_eq!(st.truncated_values, 1);
}
