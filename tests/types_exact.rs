//! Exact result JSON and column type names for types.all_types, on every test server.
//! Expected values follow the value-encoding table in README.md; PostgreSQL's own text is the
//! source for text-typed values.

mod common;

use common::{PORT_15, PORT_18, PORT_19, app, call_tool, one_db, result_of};
use serde_json::{Value, json};

/// Column name and type name for each column of types.all_types, in SELECT order.
/// A domain column reports its base type, as PostgreSQL's RowDescription does.
const COLUMNS: &[(&str, &str)] = &[
    ("id", "int4"),
    ("c_bool", "bool"),
    ("c_int2", "int2"),
    ("c_int4", "int4"),
    ("c_int8", "int8"),
    ("c_float4", "float4"),
    ("c_float8", "float8"),
    ("c_numeric", "numeric"),
    ("c_money", "money"),
    ("c_text", "text"),
    ("c_varchar", "varchar"),
    ("c_bpchar", "bpchar"),
    ("c_name", "name"),
    ("c_char", "char"),
    ("c_bytea", "bytea"),
    ("c_uuid", "uuid"),
    ("c_date", "date"),
    ("c_time", "time"),
    ("c_timetz", "timetz"),
    ("c_timestamp", "timestamp"),
    ("c_timestamptz", "timestamptz"),
    ("c_interval", "interval"),
    ("c_json", "json"),
    ("c_jsonb", "jsonb"),
    ("c_xml", "xml"),
    ("c_bit", "bit"),
    ("c_varbit", "varbit"),
    ("c_inet", "inet"),
    ("c_cidr", "cidr"),
    ("c_macaddr", "macaddr"),
    ("c_macaddr8", "macaddr8"),
    ("c_point", "point"),
    ("c_line", "line"),
    ("c_lseg", "lseg"),
    ("c_box", "box"),
    ("c_path", "path"),
    ("c_polygon", "polygon"),
    ("c_circle", "circle"),
    ("c_tsvector", "tsvector"),
    ("c_tsquery", "tsquery"),
    ("c_jsonpath", "jsonpath"),
    ("c_pg_lsn", "pg_lsn"),
    ("c_xid8", "xid8"),
    ("c_oid", "oid"),
    ("c_regclass", "regclass"),
    ("c_regtype", "regtype"),
    ("c_int4range", "int4range"),
    ("c_int8range", "int8range"),
    ("c_numrange", "numrange"),
    ("c_tsrange", "tsrange"),
    ("c_tstzrange", "tstzrange"),
    ("c_daterange", "daterange"),
    ("c_int4multirange", "int4multirange"),
    ("c_datemultirange", "datemultirange"),
    ("c_floatrange", "types.floatrange"),
    ("c_mood", "types.mood"),
    ("c_pair", "types.pair"),
    ("c_posint", "int4"),
    ("c_hstore", "hstore"),
    ("c_ltree", "ltree"),
    ("c_citext", "citext"),
    ("c_int4_arr", "_int4"),
    ("c_text_arr", "_text"),
    ("c_numeric_arr", "_numeric"),
    ("c_jsonb_arr", "_jsonb"),
    ("c_mood_arr", "types.mood[]"),
    ("c_int4range_arr", "_int4range"),
    ("c_timestamptz_arr", "_timestamptz"),
    ("c_box_arr", "_box"),
    ("c_int2vector", "int2vector"),
    ("c_pg_snapshot", "pg_snapshot"),
];

/// Row 1: the typical values.
const ROW1: &str = r##"{"id":1,"c_bool":true,"c_int2":7,"c_int4":1000,"c_int8":42,
"c_float4":1.5,"c_float8":0.1,"c_numeric":"12345.6789","c_money":"$12.34","c_text":"hello",
"c_varchar":"varchar","c_bpchar":"abc  ","c_name":"name1","c_char":"a","c_bytea":"\\xdeadbeef",
"c_uuid":"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11","c_date":"2024-02-29","c_time":"13:00:00.5",
"c_timetz":"13:00:00+05:30","c_timestamp":"2024-02-29 13:00:00.123456",
"c_timestamptz":"2024-02-29 07:30:00.123456+00","c_interval":"P1Y2M3DT4H5M6.789S",
"c_json":{"a":1,"b":[1,2,{"c":null}]},"c_jsonb":{"a":1,"b":[1,2,{"c":null}]},"c_xml":"<a>1</a>",
"c_bit":"1010","c_varbit":"101","c_inet":"192.168.1.5/24","c_cidr":"10.0.0.0/8",
"c_macaddr":"08:00:2b:01:02:03","c_macaddr8":"08:00:2b:01:02:03:04:05","c_point":"(1,2)",
"c_line":"{1,-1,0}","c_lseg":"[(0,0),(1,1)]","c_box":"(1,1),(0,0)","c_path":"((0,0),(1,0),(1,1))",
"c_polygon":"((0,0),(1,0),(0,1))","c_circle":"<(1,2),3>","c_tsvector":"'cat':3 'fat':2",
"c_tsquery":"'fat' & 'rat'","c_jsonpath":"$.\"a\"[*]?(@ > 1)","c_pg_lsn":"16/B374D848",
"c_xid8":42,"c_oid":42,"c_regclass":"pg_class","c_regtype":"integer",
"c_int4range":{"lower":1,"upper":5,"lowerInc":true,"upperInc":false},
"c_int8range":{"lower":1,"upper":9,"lowerInc":true,"upperInc":false},
"c_numrange":{"lower":"1.5","upper":"2.5","lowerInc":false,"upperInc":true},
"c_tsrange":{"lower":"2024-01-01 00:00:00","upper":"2024-01-02 00:00:00","lowerInc":true,"upperInc":false},
"c_tstzrange":{"lower":"2024-01-01 00:00:00+00","upper":"2024-01-02 00:00:00+00","lowerInc":true,"upperInc":false},
"c_daterange":{"lower":"2024-01-01","upper":"2024-02-01","lowerInc":true,"upperInc":false},
"c_int4multirange":[{"lower":1,"upper":3,"lowerInc":true,"upperInc":false},{"lower":5,"upper":8,"lowerInc":true,"upperInc":false}],
"c_datemultirange":[{"lower":"2024-01-01","upper":"2024-02-01","lowerInc":true,"upperInc":false}],
"c_floatrange":{"lower":0.5,"upper":1.5,"lowerInc":true,"upperInc":false},
"c_mood":"happy","c_pair":"(1,\"x, y\")","c_posint":5,"c_hstore":"\"a\"=>\"1\", \"b\"=>NULL",
"c_ltree":"a.b.c","c_citext":"AbC","c_int4_arr":[1,2,3],"c_text_arr":["a b","c"],
"c_numeric_arr":["1.5","2"],"c_jsonb_arr":[{"x":1},[3]],"c_mood_arr":["happy","ok"],
"c_int4range_arr":[{"lower":1,"upper":3,"lowerInc":true,"upperInc":false},{"lower":5,"upper":8,"lowerInc":true,"upperInc":false}],
"c_timestamptz_arr":["2024-01-01 00:00:00+00","2024-06-01 12:00:00+00"],
"c_box_arr":["(1,1),(0,0)"],"c_int2vector":"1 2 3","c_pg_snapshot":"10:20:10,14,15"}"##;

/// Row 2: the edge values. Its c_pg_lsn is set per server, see the tests below.
const ROW2: &str = r##"{"id":2,"c_bool":false,"c_int2":-32768,"c_int4":2147483647,
"c_int8":"9223372036854775807","c_float4":"NaN","c_float8":"-Infinity","c_numeric":"NaN",
"c_money":"-$92,233,720,368,547,758.08","c_text":"","c_varchar":"héllo wörld ✓","c_bpchar":"ab   ",
"c_name":"x","c_char":"","c_bytea":"\\x","c_uuid":"00000000-0000-0000-0000-000000000000",
"c_date":"infinity","c_time":"24:00:00","c_timetz":"00:00:00+14",
"c_timestamp":"0044-03-15 12:00:00 BC","c_timestamptz":"-infinity","c_interval":"P-1M2DT-3H",
"c_json":"{\"a\":1,\"a\":2, \"big\":1e400}","c_jsonb":{"n":12345678901234567890.123456789},
"c_xml":"<r/>","c_bit":"0000","c_varbit":"","c_inet":"::1","c_cidr":"::/0",
"c_macaddr":"ff:ff:ff:ff:ff:ff","c_macaddr8":"00:00:00:00:00:00:00:00","c_point":"(0,0)",
"c_line":"{0,1,-0.5}","c_lseg":"[(1,1),(0,0)]","c_box":"(3,3),(2,2)","c_path":"[(0,0),(1,1)]",
"c_polygon":"((0,0),(1,1),(1,0))","c_circle":"<(0,0),0>","c_tsvector":"","c_tsquery":"'a' <-> 'b'",
"c_jsonpath":"$","c_pg_lsn":"0/0","c_xid8":"18446744073709551615","c_oid":4294967295,
"c_regclass":"pg_type","c_regtype":"text[]","c_int4range":{"empty":true},
"c_int8range":{"lower":null,"upper":null,"lowerInc":false,"upperInc":false},
"c_numrange":{"lower":"1.5","upper":null,"lowerInc":true,"upperInc":false},
"c_tsrange":{"lower":null,"upper":"2024-01-01 00:00:00","lowerInc":false,"upperInc":true},
"c_tstzrange":{"lower":"2024-01-01 00:00:00+00","upper":"2024-12-31 23:59:59+00","lowerInc":true,"upperInc":true},
"c_daterange":{"lower":null,"upper":"2024-01-02","lowerInc":false,"upperInc":false},
"c_int4multirange":[],"c_datemultirange":[],
"c_floatrange":{"lower":1.5,"upper":2.5,"lowerInc":true,"upperInc":true},
"c_mood":"sad","c_pair":"(,)","c_posint":2147483647,"c_hstore":"\"k\"=>\"\"",
"c_ltree":"top_1.Sci_2","c_citext":"ÄÖ",
"c_int4_arr":{"lowerBounds":[2,0],"elements":[[1,null],[3,4]]},
"c_text_arr":["NULL",null,"c\"d","e\\f",""],"c_numeric_arr":["1.50","NaN","Infinity"],
"c_jsonb_arr":[{"a":1},[1,2]],"c_mood_arr":["sad",null,"happy"],
"c_int4range_arr":[{"lower":1,"upper":2,"lowerInc":true,"upperInc":false},{"empty":true}],
"c_timestamptz_arr":["2024-01-01 00:00:00+00","infinity"],
"c_box_arr":["(1,1),(0,0)","(3,3),(2,2)"],"c_int2vector":"-1 0 32767","c_pg_snapshot":"1:1:"}"##;

/// Row ids are 1, 2 and 3; row 3 is NULL in every column except id.
fn all_null_row(id: u64) -> Value {
    let mut row = serde_json::Map::new();
    for (name, _) in COLUMNS {
        row.insert((*name).to_string(), Value::Null);
    }
    row.insert("id".to_string(), json!(id));
    Value::Object(row)
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("expected JSON")
}

fn expected_columns() -> Vec<(String, String)> {
    COLUMNS
        .iter()
        .map(|(name, ty)| ((*name).to_string(), (*ty).to_string()))
        .collect()
}

/// Runs one execute_query on the server at `port` and returns its structuredContent.
async fn query(port: u16, sql: &str) -> Value {
    let router = app(one_db(port, &[]));
    let response = call_tool(&router, "execute_query", json!({"sql": sql})).await;
    let result = result_of(&response);
    assert_eq!(result["isError"], json!(false), "{response}");
    result["structuredContent"].clone()
}

fn column_types(body: &Value) -> Vec<(String, String)> {
    body["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .map(|c| {
            (
                c["name"].as_str().expect("name").to_string(),
                c["type"].as_str().expect("type").to_string(),
            )
        })
        .collect()
}

/// PostgreSQL 19 prints a zero pg_lsn as 0/00000000; PostgreSQL 15 and 18 print 0/0.
async fn check_all_types(port: u16, zero_lsn: &str) {
    let body = query(port, "SELECT * FROM types.all_types ORDER BY id").await;
    assert_eq!(column_types(&body), expected_columns());
    let mut row2 = parse(ROW2);
    row2["c_pg_lsn"] = json!(zero_lsn);
    assert_eq!(
        body["rows"],
        Value::Array(vec![parse(ROW1), row2, all_null_row(3)])
    );
    assert_eq!(body["rowCount"], json!(3));
    assert_eq!(body["truncated"], json!(false));
    assert_eq!(body["truncatedValues"], json!(0));
    // Only the duplicate-key json document in row 2 is returned as its text.
    assert_eq!(body["rawFallbacks"], json!(1));
}

#[tokio::test]
async fn all_types_exact_on_pg18() {
    check_all_types(PORT_18, "0/0").await;
}

#[tokio::test]
async fn all_types_exact_on_pg19() {
    check_all_types(PORT_19, "0/00000000").await;
}

#[tokio::test]
async fn all_types_exact_on_pg15() {
    check_all_types(PORT_15, "0/0").await;
}

#[tokio::test]
async fn oid8_column_is_exact_on_pg19() {
    let body = query(PORT_19, "SELECT * FROM types.ext_types ORDER BY id").await;
    assert_eq!(
        column_types(&body),
        vec![
            ("id".to_string(), "int4".to_string()),
            ("c_oid8".to_string(), "oid8".to_string()),
        ]
    );
    assert_eq!(
        body["rows"],
        json!([{"id": 1, "c_oid8": "18446744073709551615"}])
    );
}

#[tokio::test]
async fn vector_columns_are_exact_on_pg18() {
    let body = query(PORT_18, "SELECT * FROM types.vec_types ORDER BY id").await;
    assert_eq!(
        column_types(&body),
        vec![
            ("id".to_string(), "int4".to_string()),
            ("c_vector".to_string(), "vector".to_string()),
            ("c_halfvec".to_string(), "halfvec".to_string()),
            ("c_sparsevec".to_string(), "sparsevec".to_string()),
        ]
    );
    assert_eq!(
        body["rows"],
        json!([{
            "id": 1,
            "c_vector": "[1,2,3]",
            "c_halfvec": "[1,2,3]",
            "c_sparsevec": "{1:1,3:2}/5"
        }])
    );
}

#[tokio::test]
async fn postgis_columns_are_exact_on_pg18() {
    let body = query(PORT_18, "SELECT * FROM types.geo_types ORDER BY id").await;
    assert_eq!(
        column_types(&body),
        vec![
            ("id".to_string(), "int4".to_string()),
            ("c_geometry".to_string(), "geometry".to_string()),
            ("c_geography".to_string(), "geography".to_string()),
        ]
    );
    let point = "0101000020E61000009A99999999F951C03333333333B34640";
    assert_eq!(
        body["rows"],
        json!([{"id": 1, "c_geometry": point, "c_geography": point}])
    );
}
