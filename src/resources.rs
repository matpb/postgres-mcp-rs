//! MCP resources and completions: a summary per database, and the schema and table views the tools return.

use std::collections::HashMap;
use std::time::Instant;

use rmcp::ErrorData as McpError;
use rmcp::model::{
    CompleteRequestParams, CompleteResult, CompletionInfo, ListResourceTemplatesResult,
    ListResourcesResult, ReadResourceResult, Reference, Resource, ResourceContents,
    ResourceTemplate,
};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::scrub;
use crate::server::AppState;
use crate::tools::core::{self, DatabaseArgs};
use crate::tools::schema::NON_SYSTEM;
use crate::tools::schema::describe::{self, DescribeTableArgs};
use crate::tools::schema::listing::{self, ListObjectsArgs, ListSchemasArgs};
use crate::tools::text;
use crate::tools::{Call, Runner, ToolError};

const SCHEME: &str = "postgres://";
const JSON_MIME: &str = "application/json";
const SCHEMA_TEMPLATE: &str = "postgres://{database}/{schema}";
const TABLE_TEMPLATE: &str = "postgres://{database}/{schema}/{table}";

/// Tables, views, materialized views, foreign tables and partitioned tables of one schema, by name.
const TABLE_COMPLETION_SQL: &str = "SELECT c.relname::text AS name, pg_catalog.count(*) OVER () AS total \
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
    WHERE n.nspname::text = $1::text AND c.relkind::text IN ('r', 'p', 'v', 'm', 'f') \
    AND (pg_catalog.pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') \
         OR pg_catalog.has_schema_privilege(n.oid, 'USAGE')) \
    AND pg_catalog.starts_with(pg_catalog.lower(c.relname::text), pg_catalog.lower($2::text)) \
    ORDER BY c.relname::text COLLATE \"C\" LIMIT 100";

/// The database resource's list entry, one per configured database in configuration order.
pub fn list(state: &AppState) -> ListResourcesResult {
    let resources = state
        .config
        .databases
        .iter()
        .map(|db| {
            Resource::new(format!("{SCHEME}{}", db.name), db.name.clone())
                .with_title(format!("{} {}", text::RESOURCE_DATABASE_TITLE, db.name))
                .with_mime_type(JSON_MIME)
                .with_description(text::RESOURCE_DATABASE_DESCRIPTION)
        })
        .collect();
    ListResourcesResult::with_all_items(resources)
}

/// The two resource templates: one schema, and one table or view of a schema.
pub fn templates() -> ListResourceTemplatesResult {
    ListResourceTemplatesResult::with_all_items(vec![
        ResourceTemplate::new(SCHEMA_TEMPLATE, "schema")
            .with_title(text::RESOURCE_SCHEMA_TITLE)
            .with_mime_type(JSON_MIME)
            .with_description(text::RESOURCE_SCHEMA_DESCRIPTION),
        ResourceTemplate::new(TABLE_TEMPLATE, "table")
            .with_title(text::RESOURCE_TABLE_TITLE)
            .with_mime_type(JSON_MIME)
            .with_description(text::RESOURCE_TABLE_DESCRIPTION),
    ])
}

/// The parts of a resource URI, with each name percent-decoded.
#[derive(Debug, PartialEq)]
enum Target {
    Database(String),
    Schema {
        database: String,
        schema: String,
    },
    Table {
        database: String,
        schema: String,
        table: String,
    },
}

/// Splits a postgres:// URI on its raw slashes, then decodes each name; None for any other shape.
fn parse(uri: &str) -> Option<Target> {
    let path = uri.strip_prefix(SCHEME)?;
    if path.contains(['?', '#']) {
        return None;
    }
    let parts = path
        .split('/')
        .map(decode)
        .collect::<Option<Vec<String>>>()?;
    if parts.iter().any(String::is_empty) {
        return None;
    }
    match parts.as_slice() {
        [database] => Some(Target::Database(database.clone())),
        [database, schema] => Some(Target::Schema {
            database: database.clone(),
            schema: schema.clone(),
        }),
        [database, schema, table] => Some(Target::Table {
            database: database.clone(),
            schema: schema.clone(),
            table: table.clone(),
        }),
        _ => None,
    }
}

/// Percent-decodes one URI segment; None for a malformed escape, a NUL byte, or bytes that are not UTF-8.
fn decode(segment: &str) -> Option<String> {
    let mut out = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let high = (bytes.next()? as char).to_digit(16)?;
        let low = (bytes.next()? as char).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    if out.contains(&0) {
        return None;
    }
    String::from_utf8(out).ok()
}

/// Reads one resource. Each read writes one audit line; an unknown URI shape writes none, as an unknown tool does not.
pub async fn read(
    state: &AppState,
    uri: &str,
    ct: &CancellationToken,
) -> Result<ReadResourceResult, McpError> {
    let Some(target) = parse(uri) else {
        return Err(McpError::resource_not_found(
            text::UNKNOWN_RESOURCE_URI,
            None,
        ));
    };
    let started = Instant::now();
    let (tool, requested, outcome) = match target {
        Target::Database(database) => {
            let outcome = summary(state, &database, ct).await;
            ("resource:database", database, outcome)
        }
        Target::Schema { database, schema } => {
            let outcome = schema_listing(state, &database, &schema, ct).await;
            ("resource:schema", database, outcome)
        }
        Target::Table {
            database,
            schema,
            table,
        } => {
            let outcome = table_definition(state, &database, &schema, &table, ct).await;
            ("resource:table", database, outcome)
        }
    };
    let ok = outcome.is_ok();
    let sqlstate = outcome
        .as_ref()
        .err()
        .and_then(ToolError::sqlstate)
        .map(str::to_owned);
    // The final pass runs on the value before it is serialized. The count is the markers in the body.
    let outcome = match outcome {
        Ok((name, mut value)) => {
            crate::tools::mask::scrub_and_mask(&mut value, &[], &[]);
            scrub::set_total(scrub::count_markers(&value));
            Ok((name, value))
        }
        Err(error) => Err(read_error(error)),
    };
    let redacted_hashes = scrub::total();
    let database = match &outcome {
        Ok((name, _)) => Some(name.clone()),
        Err(_) => state.resolve_name(Some(&requested)),
    };
    audit::record(
        state.config.audit_log,
        &audit::Record {
            tool,
            database: database.as_deref(),
            ok,
            duration: started.elapsed(),
            rows: None,
            sqlstate: sqlstate.as_deref(),
            sql: None,
            redacted_hashes,
        },
    );
    if redacted_hashes > 0 {
        tracing::warn!(
            tool,
            database = database.as_deref(),
            count = redacted_hashes,
            "password hash text was redacted from a result"
        );
    }
    match outcome {
        Ok((_, value)) => {
            let json = value.to_string();
            let (text, found) = scrub::scrub_counting(&json);
            if found > 0 {
                tracing::warn!(
                    tool,
                    count = found,
                    "output guard replaced text after the main pass"
                );
            }
            let text = text.into_owned();
            Ok(ReadResourceResult::new(vec![
                ResourceContents::text(text, scrub::scrub(uri).into_owned())
                    .with_mime_type(JSON_MIME),
            ]))
        }
        Err(error) => Err(error),
    }
}

/// Unknown names are resource-not-found with the tool's text; any other failure is an internal error with its short text.
fn read_error(error: ToolError) -> McpError {
    let (text, not_found) = match error {
        ToolError::Config(message) | ToolError::Rejected(message) => (message, true),
        other => (other.message(), false),
    };
    let (scrubbed, found) = scrub::scrub_counting(&text);
    scrub::record(found);
    if not_found {
        McpError::resource_not_found(scrubbed.into_owned(), None)
    } else {
        McpError::internal_error(scrubbed.into_owned(), None)
    }
}

/// The database summary: version and TimescaleDB from server_info, schemas from list_schemas, extensions with their schema.
async fn summary(
    state: &AppState,
    database: &str,
    ct: &CancellationToken,
) -> Result<(String, Value), ToolError> {
    let info = core::server_info(
        state,
        DatabaseArgs {
            database: Some(database.to_owned()),
        },
        ct,
    )
    .await
    .result?;
    let schemas = listing::list_schemas(
        state,
        ListSchemasArgs {
            database: Some(database.to_owned()),
            include_system: false,
        },
        ct,
    )
    .await
    .result?;
    let rows = Runner::new(state)
        .internal_query(Some(database), core::EXTENSIONS_SQL, &[], ct)
        .await?
        .rows;
    let extensions: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "name": row.get("name"),
                "version": row.get("version"),
                "schema": row.get("schema"),
            })
        })
        .collect();
    let value = json!({
        "database": database,
        "serverVersion": info["version"]["full"],
        "serverVersionNum": info["version"]["number"],
        "timescaledb": info["timescaledb"],
        "schemas": schemas["schemas"],
        "extensions": extensions,
    });
    Ok((database.to_owned(), value))
}

/// The list_objects tool's first page for one schema.
async fn schema_listing(
    state: &AppState,
    database: &str,
    schema: &str,
    ct: &CancellationToken,
) -> Result<(String, Value), ToolError> {
    let args = ListObjectsArgs {
        database: Some(database.to_owned()),
        schema: Some(schema.to_owned()),
        kinds: None,
        name_like: None,
        limit: None,
        cursor: None,
    };
    let call: Call = listing::list_objects(state, args, ct).await;
    Ok((
        call.database.unwrap_or_else(|| database.to_owned()),
        call.result?,
    ))
}

/// The describe_table tool's result for one table or view.
async fn table_definition(
    state: &AppState,
    database: &str,
    schema: &str,
    table: &str,
    ct: &CancellationToken,
) -> Result<(String, Value), ToolError> {
    let args = DescribeTableArgs {
        database: Some(database.to_owned()),
        table: table.to_owned(),
        schema: Some(schema.to_owned()),
    };
    let call: Call = describe::describe_table(state, args, ct).await;
    Ok((
        call.database.unwrap_or_else(|| database.to_owned()),
        call.result?,
    ))
}

/// Completions for the database, schema and table arguments of the two templates. Any other request,
/// and any database error, is an empty completion.
pub async fn complete(
    state: &AppState,
    request: CompleteRequestParams,
    ct: &CancellationToken,
) -> CompleteResult {
    let Reference::Resource(reference) = &request.r#ref else {
        return completion(Vec::new(), 0);
    };
    let template = reference.uri.as_str();
    if template != SCHEMA_TEMPLATE && template != TABLE_TEMPLATE {
        return completion(Vec::new(), 0);
    }
    let prefix = request.argument.value.as_str();
    let arguments = request
        .context
        .as_ref()
        .and_then(|context| context.arguments.as_ref());
    let values = match request.argument.name.as_str() {
        "database" => Some(database_values(state, prefix)),
        "schema" => schema_values(state, arguments, prefix, ct).await,
        "table" if template == TABLE_TEMPLATE => table_values(state, arguments, prefix, ct).await,
        _ => None,
    };
    match values {
        Some((names, total)) => completion(names, total),
        None => completion(Vec::new(), 0),
    }
}

/// A completion of at most the protocol's value limit; `total` is the full number of matches.
fn completion(values: Vec<String>, total: usize) -> CompleteResult {
    let cut = total > values.len();
    let info = if cut {
        CompletionInfo::with_pagination(values, u32::try_from(total).ok(), true)
    } else {
        CompletionInfo::new(values)
    };
    CompleteResult::new(info.unwrap_or_default())
}

/// Configured database names starting with the prefix, case-insensitively, in name order.
fn database_values(state: &AppState, prefix: &str) -> (Vec<String>, usize) {
    let wanted = prefix.to_lowercase();
    let mut names: Vec<String> = state
        .config
        .databases
        .iter()
        .map(|db| db.name.clone())
        .filter(|name| name.to_lowercase().starts_with(&wanted))
        .collect();
    names.sort();
    let total = names.len();
    names.truncate(CompletionInfo::MAX_VALUES);
    (names, total)
}

/// The database a schema or table completion reads: the context argument, or the only configured database.
fn completion_database(
    state: &AppState,
    arguments: Option<&HashMap<String, String>>,
) -> Option<String> {
    match arguments.and_then(|args| args.get("database")) {
        Some(name) => Some(name.clone()),
        None => match state.config.databases.as_slice() {
            [only] => Some(only.name.clone()),
            _ => None,
        },
    }
}

/// Schemas starting with the prefix. System schemas are listed only when the prefix starts with pg_ or information_schema.
async fn schema_values(
    state: &AppState,
    arguments: Option<&HashMap<String, String>>,
    prefix: &str,
    ct: &CancellationToken,
) -> Option<(Vec<String>, usize)> {
    let database = completion_database(state, arguments)?;
    let lowered = prefix.to_lowercase();
    let include_system = lowered.starts_with("pg_") || lowered.starts_with("information_schema");
    let include_system = if include_system { "true" } else { "false" };
    let rows = Runner::new(state)
        .internal_query(
            Some(database.as_str()),
            &schema_completion_sql(),
            &[Some(prefix), Some(include_system)],
            ct,
        )
        .await
        .ok()?
        .rows;
    Some(names_and_total(rows))
}

/// Tables and views of the context schema starting with the prefix; no schema in the context is an empty completion.
async fn table_values(
    state: &AppState,
    arguments: Option<&HashMap<String, String>>,
    prefix: &str,
    ct: &CancellationToken,
) -> Option<(Vec<String>, usize)> {
    let database = completion_database(state, arguments)?;
    let schema = arguments.and_then(|args| args.get("schema"))?;
    let rows = Runner::new(state)
        .internal_query(
            Some(database.as_str()),
            TABLE_COMPLETION_SQL,
            &[Some(schema.as_str()), Some(prefix)],
            ct,
        )
        .await
        .ok()?
        .rows;
    Some(names_and_total(rows))
}

/// Schemas the role may see, as list_schemas shows them, starting with $1 case-insensitively; $2 includes system schemas.
fn schema_completion_sql() -> String {
    format!(
        "SELECT n.nspname::text AS name, pg_catalog.count(*) OVER () AS total \
        FROM pg_catalog.pg_namespace n \
        WHERE pg_catalog.starts_with(pg_catalog.lower(n.nspname::text), pg_catalog.lower($1::text)) \
        AND ($2::boolean OR {NON_SYSTEM}) \
        AND (pg_catalog.pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') \
             OR pg_catalog.has_schema_privilege(n.oid, 'USAGE')) \
        ORDER BY n.nspname::text COLLATE \"C\" LIMIT 100"
    )
}

/// The names of the returned rows, and the total match count that the first row's window column reports.
fn names_and_total(rows: Vec<Map<String, Value>>) -> (Vec<String>, usize) {
    let total = rows
        .first()
        .and_then(|row| count_of(row.get("total")))
        .unwrap_or(0);
    let names = rows
        .iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect();
    (names, total)
}

/// A count as the envelope encodes it: a JSON number, or a string for values past 2^53-1.
fn count_of(value: Option<&Value>) -> Option<usize> {
    let number = match value? {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => s.parse::<u64>().ok()?,
        _ => return None,
    };
    usize::try_from(number).ok()
}

#[cfg(test)]
mod tests {
    use super::{Target, decode, parse};

    #[test]
    fn slashes_split_before_decoding() {
        assert_eq!(
            parse("postgres://appdb/shop/a%2Fb"),
            Some(Target::Table {
                database: "appdb".into(),
                schema: "shop".into(),
                table: "a/b".into(),
            })
        );
    }

    #[test]
    fn malformed_uris_have_no_target() {
        for uri in [
            "postgres://",
            "postgres://appdb/",
            "postgres:///shop",
            "postgres://appdb/a/b/c/d",
            "postgres://appdb/shop?x=1",
            "postgres://appdb/shop#frag",
            "postgres://appdb/%zz",
            "postgres://appdb/%+1",
            "postgres://appdb/%ff",
            "http://appdb",
        ] {
            assert_eq!(parse(uri), None, "{uri}");
        }
    }

    #[test]
    fn escapes_decode_to_bytes() {
        assert_eq!(decode("Odd%2EName").as_deref(), Some("Odd.Name"));
        assert_eq!(decode("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode("%C3%A9").as_deref(), Some("é"));
        assert_eq!(decode("plain+sign").as_deref(), Some("plain+sign"));
    }
}
