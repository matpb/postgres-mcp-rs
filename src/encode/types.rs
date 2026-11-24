//! Built-in PostgreSQL types keyed by OID.

/// How a value of a type is decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Bool,
    Int,
    BigInt,
    Float,
    Numeric,
    Json,
    Bytea,
    /// Returned as a JSON string exactly as Postgres printed it.
    Text,
    Array {
        elem: Box<TypeInfo>,
        delim: char,
    },
    Range {
        sub: Box<TypeInfo>,
    },
    Multirange {
        sub: Box<TypeInfo>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeInfo {
    pub oid: u32,
    pub name: String,
    pub kind: TypeKind,
}

#[derive(Clone, Copy)]
enum Leaf {
    Bool,
    Int,
    BigInt,
    Float,
    Numeric,
    Json,
    Bytea,
    Text,
}

const LEAVES: &[(u32, &str, Leaf)] = &[
    (16, "bool", Leaf::Bool),
    (21, "int2", Leaf::Int),
    (23, "int4", Leaf::Int),
    (26, "oid", Leaf::Int),
    (28, "xid", Leaf::Int),
    (29, "cid", Leaf::Int),
    (20, "int8", Leaf::BigInt),
    (5069, "xid8", Leaf::BigInt),
    (6437, "oid8", Leaf::BigInt),
    (700, "float4", Leaf::Float),
    (701, "float8", Leaf::Float),
    (1700, "numeric", Leaf::Numeric),
    (114, "json", Leaf::Json),
    (3802, "jsonb", Leaf::Json),
    (17, "bytea", Leaf::Bytea),
    (18, "char", Leaf::Text),
    (19, "name", Leaf::Text),
    (25, "text", Leaf::Text),
    (1042, "bpchar", Leaf::Text),
    (1043, "varchar", Leaf::Text),
    (2950, "uuid", Leaf::Text),
    (142, "xml", Leaf::Text),
    (1082, "date", Leaf::Text),
    (1083, "time", Leaf::Text),
    (1114, "timestamp", Leaf::Text),
    (1184, "timestamptz", Leaf::Text),
    (1266, "timetz", Leaf::Text),
    (1186, "interval", Leaf::Text),
    (790, "money", Leaf::Text),
    (1560, "bit", Leaf::Text),
    (1562, "varbit", Leaf::Text),
    (869, "inet", Leaf::Text),
    (650, "cidr", Leaf::Text),
    (829, "macaddr", Leaf::Text),
    (774, "macaddr8", Leaf::Text),
    (600, "point", Leaf::Text),
    (601, "lseg", Leaf::Text),
    (602, "path", Leaf::Text),
    (603, "box", Leaf::Text),
    (604, "polygon", Leaf::Text),
    (628, "line", Leaf::Text),
    (718, "circle", Leaf::Text),
    (3614, "tsvector", Leaf::Text),
    (3615, "tsquery", Leaf::Text),
    (4072, "jsonpath", Leaf::Text),
    (3220, "pg_lsn", Leaf::Text),
    (5038, "pg_snapshot", Leaf::Text),
    (2970, "txid_snapshot", Leaf::Text),
    (2205, "regclass", Leaf::Text),
    (2206, "regtype", Leaf::Text),
    (24, "regproc", Leaf::Text),
    (2202, "regprocedure", Leaf::Text),
    (2203, "regoper", Leaf::Text),
    (2204, "regoperator", Leaf::Text),
    (3734, "regconfig", Leaf::Text),
    (3769, "regdictionary", Leaf::Text),
    (4089, "regnamespace", Leaf::Text),
    (4096, "regrole", Leaf::Text),
    (4191, "regcollation", Leaf::Text),
    (22, "int2vector", Leaf::Text),
    (30, "oidvector", Leaf::Text),
    (2249, "record", Leaf::Text),
    (705, "unknown", Leaf::Text),
    (2278, "void", Leaf::Text),
];

/// Array types: (oid, name, element oid, delimiter).
const ARRAYS: &[(u32, &str, u32, char)] = &[
    (1000, "_bool", 16, ','),
    (1005, "_int2", 21, ','),
    (1007, "_int4", 23, ','),
    (1016, "_int8", 20, ','),
    (1021, "_float4", 700, ','),
    (1022, "_float8", 701, ','),
    (1231, "_numeric", 1700, ','),
    (1009, "_text", 25, ','),
    (1015, "_varchar", 1043, ','),
    (1014, "_bpchar", 1042, ','),
    (1003, "_name", 19, ','),
    (2951, "_uuid", 2950, ','),
    (199, "_json", 114, ','),
    (3807, "_jsonb", 3802, ','),
    (1001, "_bytea", 17, ','),
    (1182, "_date", 1082, ','),
    (1183, "_time", 1083, ','),
    (1115, "_timestamp", 1114, ','),
    (1185, "_timestamptz", 1184, ','),
    (1270, "_timetz", 1266, ','),
    (1187, "_interval", 1186, ','),
    (1041, "_inet", 869, ','),
    (651, "_cidr", 650, ','),
    (1040, "_macaddr", 829, ','),
    (1028, "_oid", 26, ','),
    (791, "_money", 790, ','),
    (1561, "_bit", 1560, ','),
    (1563, "_varbit", 1562, ','),
    (1017, "_point", 600, ','),
    (1020, "_box", 603, ';'),
    (3643, "_tsvector", 3614, ','),
    (3645, "_tsquery", 3615, ','),
    (143, "_xml", 142, ','),
    (3905, "_int4range", 3904, ','),
    (3927, "_int8range", 3926, ','),
    (3907, "_numrange", 3906, ','),
    (3909, "_tsrange", 3908, ','),
    (3911, "_tstzrange", 3910, ','),
    (3913, "_daterange", 3912, ','),
];

/// Range types: (oid, name, subtype oid).
const RANGES: &[(u32, &str, u32)] = &[
    (3904, "int4range", 23),
    (3926, "int8range", 20),
    (3906, "numrange", 1700),
    (3908, "tsrange", 1114),
    (3910, "tstzrange", 1184),
    (3912, "daterange", 1082),
];

/// Multirange types: (oid, name, subtype oid).
const MULTIRANGES: &[(u32, &str, u32)] = &[
    (4451, "int4multirange", 23),
    (4536, "int8multirange", 20),
    (4532, "nummultirange", 1700),
    (4533, "tsmultirange", 1114),
    (4534, "tstzmultirange", 1184),
    (4535, "datemultirange", 1082),
];

/// Built-in type by OID; None for anything else.
pub fn builtin_type(oid: u32) -> Option<TypeInfo> {
    if let Some(&(_, name, leaf)) = LEAVES.iter().find(|r| r.0 == oid) {
        return Some(TypeInfo {
            oid,
            name: name.to_string(),
            kind: leaf_kind(leaf),
        });
    }
    if let Some(&(_, name, elem, delim)) = ARRAYS.iter().find(|r| r.0 == oid) {
        let elem = builtin_type(elem)?;
        return Some(TypeInfo {
            oid,
            name: name.to_string(),
            kind: TypeKind::Array {
                elem: Box::new(elem),
                delim,
            },
        });
    }
    if let Some(&(_, name, sub)) = RANGES.iter().find(|r| r.0 == oid) {
        let sub = builtin_type(sub)?;
        return Some(TypeInfo {
            oid,
            name: name.to_string(),
            kind: TypeKind::Range { sub: Box::new(sub) },
        });
    }
    if let Some(&(_, name, sub)) = MULTIRANGES.iter().find(|r| r.0 == oid) {
        let sub = builtin_type(sub)?;
        return Some(TypeInfo {
            oid,
            name: name.to_string(),
            kind: TypeKind::Multirange { sub: Box::new(sub) },
        });
    }
    None
}

fn leaf_kind(leaf: Leaf) -> TypeKind {
    match leaf {
        Leaf::Bool => TypeKind::Bool,
        Leaf::Int => TypeKind::Int,
        Leaf::BigInt => TypeKind::BigInt,
        Leaf::Float => TypeKind::Float,
        Leaf::Numeric => TypeKind::Numeric,
        Leaf::Json => TypeKind::Json,
        Leaf::Bytea => TypeKind::Bytea,
        Leaf::Text => TypeKind::Text,
    }
}
