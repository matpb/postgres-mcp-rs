//! Resolves column type OIDs: built-ins from the static table, other types from pg_type, cached per OID.
// WireError holds DbError by value, which is large (fixed by the wire interface).
#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::encode::{TypeInfo, TypeKind, builtin_type};
use crate::pg::wire::{Connection, WireError};

/// Depth limit for element, domain-base and range-subtype chains; deeper types decode as Text.
const MAX_DEPTH: usize = 8;

/// Non-built-in types already looked up in pg_type. Unresolvable OIDs are never stored.
pub struct TypeCache {
    entries: Mutex<HashMap<u32, TypeInfo>>,
    lookups: AtomicU64,
}

impl TypeCache {
    pub fn new() -> TypeCache {
        TypeCache {
            entries: Mutex::new(HashMap::new()),
            lookups: AtomicU64::new(0),
        }
    }

    /// Number of pg_type queries sent on behalf of this cache.
    pub fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::Relaxed)
    }

    /// TypeInfo for each OID, in order. Unknown OIDs become name "unknown" with kind Text, uncached.
    pub async fn resolve(
        &self,
        conn: &mut Connection,
        oids: &[u32],
    ) -> Result<Vec<TypeInfo>, WireError> {
        let mut found: HashMap<u32, TypeInfo> = HashMap::new();
        let mut pending: Vec<u32> = Vec::new();
        {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let mut seen = HashSet::new();
            for &oid in oids {
                if builtin_type(oid).is_some() || !seen.insert(oid) {
                    continue;
                }
                match entries.get(&oid) {
                    Some(info) => {
                        found.insert(oid, info.clone());
                    }
                    None => pending.push(oid),
                }
            }
        }
        if !pending.is_empty() {
            let rows = self.load_catalog(conn, &pending).await?;
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            for &oid in &pending {
                if let Some(info) = build(oid, 0, &rows) {
                    entries.insert(oid, info.clone());
                    found.insert(oid, info);
                }
            }
        }
        Ok(oids
            .iter()
            .map(|&oid| {
                builtin_type(oid)
                    .or_else(|| found.get(&oid).cloned())
                    .unwrap_or_else(|| unknown(oid))
            })
            .collect())
    }

    /// One pg_type query per batch; follow-up batches fetch the element, base and subtype OIDs.
    async fn load_catalog(
        &self,
        conn: &mut Connection,
        pending: &[u32],
    ) -> Result<HashMap<u32, CatalogRow>, WireError> {
        let mut rows = HashMap::new();
        let mut asked: HashSet<u32> = pending.iter().copied().collect();
        let mut batch: Vec<u32> = pending.to_vec();
        for _ in 0..=MAX_DEPTH {
            if batch.is_empty() {
                break;
            }
            self.lookups.fetch_add(1, Ordering::Relaxed);
            let fetched = query_catalog(conn, &batch).await?;
            let mut next = Vec::new();
            for row in fetched {
                for child in row.children() {
                    if builtin_type(child).is_none() && asked.insert(child) {
                        next.push(child);
                    }
                }
                rows.insert(row.oid, row);
            }
            batch = next;
        }
        Ok(rows)
    }
}

impl Default for TypeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// One pg_type row with the fields the mapping needs.
struct CatalogRow {
    oid: u32,
    name: String,
    typtype: char,
    elem: u32,
    delim: char,
    base: u32,
    array_in: bool,
    range_sub: Option<u32>,
}

impl CatalogRow {
    /// OIDs this row's mapping refers to, zero excluded.
    fn children(&self) -> Vec<u32> {
        let refs = if self.array_in && self.elem != 0 {
            vec![self.elem]
        } else {
            match self.typtype {
                'd' => vec![self.base],
                'r' | 'm' => self.range_sub.into_iter().collect(),
                _ => Vec::new(),
            }
        };
        refs.into_iter().filter(|&oid| oid != 0).collect()
    }
}

fn unknown(oid: u32) -> TypeInfo {
    TypeInfo {
        oid,
        name: "unknown".into(),
        kind: TypeKind::Text,
    }
}

/// Maps one catalog-backed OID. None when pg_type has no row for it.
fn build(oid: u32, depth: usize, rows: &HashMap<u32, CatalogRow>) -> Option<TypeInfo> {
    if let Some(info) = builtin_type(oid) {
        return Some(info);
    }
    let row = rows.get(&oid)?;
    if depth >= MAX_DEPTH {
        return Some(TypeInfo {
            oid,
            name: row.name.clone(),
            kind: TypeKind::Text,
        });
    }
    if row.array_in && row.elem != 0 {
        let elem = child(row.elem, depth, rows);
        return Some(TypeInfo {
            oid,
            name: format!("{}[]", elem.name),
            kind: TypeKind::Array {
                elem: Box::new(elem),
                delim: row.delim,
            },
        });
    }
    let kind = match row.typtype {
        'd' => {
            let base = child(row.base, depth, rows);
            return Some(TypeInfo {
                oid,
                name: row.name.clone(),
                kind: base.kind,
            });
        }
        'r' => TypeKind::Range {
            sub: Box::new(child(row.range_sub.unwrap_or(0), depth, rows)),
        },
        'm' => TypeKind::Multirange {
            sub: Box::new(child(row.range_sub.unwrap_or(0), depth, rows)),
        },
        _ => TypeKind::Text,
    };
    Some(TypeInfo {
        oid,
        name: row.name.clone(),
        kind,
    })
}

/// A referenced type one level deeper; an OID that cannot be resolved becomes unknown.
fn child(oid: u32, depth: usize, rows: &HashMap<u32, CatalogRow>) -> TypeInfo {
    build(oid, depth + 1, rows).unwrap_or_else(|| unknown(oid))
}

/// Schema-qualified unless the schema is pg_catalog or public.
fn display_name(schema: &str, typname: &str) -> String {
    if schema == "pg_catalog" || schema == "public" {
        typname.to_string()
    } else {
        format!("{schema}.{typname}")
    }
}

async fn query_catalog(conn: &mut Connection, oids: &[u32]) -> Result<Vec<CatalogRow>, WireError> {
    let list: Vec<String> = oids.iter().map(u32::to_string).collect();
    let sql = format!(
        "SELECT t.oid::text, t.typname::text, n.nspname::text, t.typtype::text, t.typelem::text, \
         t.typdelim::text, t.typbasetype::text, \
         (t.typinput = 'pg_catalog.array_in'::pg_catalog.regproc)::text, \
         (SELECT r.rngsubtype::text FROM pg_catalog.pg_range r \
          WHERE r.rngtypid = t.oid OR r.rngmultitypid = t.oid LIMIT 1) \
         FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace \
         WHERE t.oid IN ({})",
        list.join(",")
    );
    let result = conn.simple_query(&sql).await?;
    result.rows.iter().map(|row| parse_row(row)).collect()
}

fn parse_row(row: &[Option<String>]) -> Result<CatalogRow, WireError> {
    let oid = parse_oid(field(row, 0)?)?;
    let typname = field(row, 1)?;
    let schema = field(row, 2)?;
    let typtype = single_char(field(row, 3)?)?;
    let elem = parse_oid(field(row, 4)?)?;
    let delim = single_char(field(row, 5)?)?;
    let base = parse_oid(field(row, 6)?)?;
    let array_in = field(row, 7)? == "true";
    let range_sub = row
        .get(8)
        .and_then(|v| v.as_deref())
        .map(parse_oid)
        .transpose()?;
    Ok(CatalogRow {
        oid,
        name: display_name(schema, typname),
        typtype,
        elem,
        delim,
        base,
        array_in,
        range_sub,
    })
}

fn field(row: &[Option<String>], index: usize) -> Result<&str, WireError> {
    row.get(index)
        .and_then(|v| v.as_deref())
        .ok_or_else(malformed)
}

fn parse_oid(text: &str) -> Result<u32, WireError> {
    text.parse().map_err(|_| malformed())
}

fn single_char(text: &str) -> Result<char, WireError> {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Ok(c),
        _ => Err(malformed()),
    }
}

fn malformed() -> WireError {
    WireError::Protocol("unexpected pg_type row".into())
}
