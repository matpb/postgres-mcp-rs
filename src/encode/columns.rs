use std::collections::HashSet;

/// Renames duplicate result columns; returns (final name, original name if renamed).
pub fn dedup_columns(names: &[String]) -> Vec<(String, Option<String>)> {
    let bases: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            if n.is_empty() {
                format!("column_{}", i + 1)
            } else {
                n.clone()
            }
        })
        .collect();
    let mut used: HashSet<String> = bases.iter().cloned().collect();
    let mut kept: HashSet<String> = HashSet::with_capacity(bases.len());
    let mut out = Vec::with_capacity(bases.len());
    for (name, base) in names.iter().zip(bases) {
        let final_name = if kept.contains(&base) {
            let mut n = 2usize;
            loop {
                let candidate = format!("{base}__{n}");
                if !used.contains(&candidate) {
                    used.insert(candidate.clone());
                    break candidate;
                }
                n += 1;
            }
        } else {
            base
        };
        kept.insert(final_name.clone());
        let original = if final_name == *name {
            None
        } else {
            Some(name.clone())
        };
        out.push((final_name, original));
    }
    out
}
