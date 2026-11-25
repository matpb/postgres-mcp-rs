//! Differential check of the PASSWORD masks over generated statements: the secret token never survives masking.

use postgres_mcp::tools::mask::{mask, mask_password_literals};

/// Statements generated and checked against each mask.
const CASES: u64 = 200_000;

/// Deterministic xorshift generator, so a failing statement reproduces from its index.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick(&mut self, items: &[&'static str]) -> &'static str {
        items[(self.next() % items.len() as u64) as usize]
    }
}

const PREFIXES: &[&str] = &[
    "",
    "SELECT 1; ",
    "DO $do$ BEGIN ",
    "DO $do$ BEGIN EXECUTE 'ALTER ROLE app ",
    "-- note\n",
    "/* c */ ",
    "x = 'y'; ",
];
const KEYWORDS: &[&str] = &["PASSWORD", "password", "Password"];
const SEPARATORS: &[&str] = &[" ", "\n", "/* c */", "-- c\n", " /**/ ", "\t"];
const SUFFIXES: &[&str] = &[
    "",
    "; SELECT 'a'",
    "'; EXECUTE 'GRANT a TO b'",
    " ) ",
    "\n-- tail\n",
    "; ALTER ROLE b PASSWORD 'z'",
];

/// The literal after the keyword, holding `token`: plain, nested, dollar-quoted or escape-string.
fn literal(form: u64, token: &str) -> String {
    match form % 9 {
        0 => format!("'{token}'"),
        1 => format!("''{token}'''"),
        2 => format!("$${token}$$"),
        3 => format!("$t${token}$t$"),
        4 => format!("E'{token}'"),
        5 => format!("E''{token}'''"),
        6 => format!("U&'{token}'"),
        7 => format!("e'{token}'"),
        _ => format!("$x_1${token}$x_1$"),
    }
}

#[test]
fn a_secret_token_never_survives_either_mask() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for index in 0..CASES {
        let token = format!("tok{index:08}");
        let pad = " ".repeat((rng.next() % 40) as usize);
        let statement = format!(
            "{}{}{}{}{}{}",
            rng.pick(PREFIXES),
            rng.pick(KEYWORDS),
            rng.pick(SEPARATORS),
            pad,
            literal(rng.next(), &token),
            rng.pick(SUFFIXES),
        );
        let literal_only = mask_password_literals(&statement);
        assert!(
            !literal_only.contains(&token),
            "literal mask kept {token} in {statement:?} -> {literal_only:?}"
        );
        let broad = mask(&statement);
        assert!(
            !broad.contains(&token),
            "broad mask kept {token} in {statement:?} -> {broad:?}"
        );
    }
}
