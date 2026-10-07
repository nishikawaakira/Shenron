use std::{fs, path::Path};

use regex::Regex;
use walkdir::WalkDir;

fn unbuffered_json_writes(file: &str, contents: &str) -> Vec<String> {
    let direct_file = Regex::new(
        r"\bto_writer(?:_pretty)?\s*\(\s*(?:[A-Za-z_][A-Za-z_0-9]*\s*::\s*)*(?:File\s*::\s*create|OpenOptions\s*::\s*new)\s*\(",
    )
    .unwrap();
    let mut problems = Vec::new();
    if direct_file.is_match(contents) {
        problems.push("direct file argument".to_owned());
    }

    // A conservative source guard, not a Rust parser or interprocedural analysis.
    // Check each function-sized region for file opening plus JSON serialization.
    // Only reviewed buffered functions and the existing append path are exempt.
    let functions = Regex::new(
        r"(?m)^[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?(?:async[ \t]+)?fn[ \t]+([A-Za-z_][A-Za-z_0-9]*)\b",
    )
    .unwrap();
    let opening = Regex::new(r"\b(?:File\s*::\s*create|OpenOptions\s*::\s*new)\s*\(").unwrap();
    let writing = Regex::new(r"(?s)\bto_writer(?:_pretty)?\s*\(\s*([^,]+),").unwrap();
    let buffered = Regex::new(r"\bBufWriter\s*::\s*(?:new|with_capacity)\s*\(").unwrap();
    let appending = Regex::new(r"\.\s*append\s*\(\s*true\s*\)").unwrap();
    let flushing = Regex::new(r"\.\s*flush\s*\(").unwrap();
    let regions: Vec<_> = functions.captures_iter(contents).collect();
    for (index, function) in regions.iter().enumerate() {
        let name = &function[1];
        let start = function.get(0).unwrap().start();
        let end = regions
            .get(index + 1)
            .map_or(contents.len(), |next| next.get(0).unwrap().start());
        let body = &contents[start..end];
        // Stdout and its named lock are intentionally outside the artifact policy.
        let writes_artifact = writing
            .captures_iter(body)
            .any(|call| !call[1].contains("stdout"));
        if !opening.is_match(body) || !writes_artifact {
            continue;
        }
        let reviewed_buffer = matches!(
            (file, name),
            ("output.rs", "write_json_pretty_buffered")
                | ("lab.rs", "generate_for_format")
                | ("processed_index.rs", "commit")
        ) && buffered.is_match(body);
        let reviewed_append = (file, name) == ("disposition.rs", "record_disposition_with_review")
            && appending.is_match(body)
            && flushing.is_match(body);
        if !reviewed_buffer && !reviewed_append {
            problems.push(format!("file opening and JSON writing in {name}"));
        }
    }
    problems
}

#[test]
fn json_artifact_guard_detects_direct_and_variable_file_writers() {
    for example in [
        "fn sample() { serde_json::to_writer(File::create(path)?, value); }",
        "fn sample() { serde_json::to_writer_pretty(\n std::fs::File::create(path)?, value); }",
        "fn sample() { serde_json::to_writer_pretty( fs :: File :: create(path)?, value); }",
        "fn sample() { serde_json::to_writer_pretty(std::fs::OpenOptions::new().write(true).create_new(true).open(path)?, value); }",
        "fn sample() { let mut file = File::create(path)?; serde_json::to_writer(&mut file, value); }",
        "fn sample() { let file = OpenOptions::new().write(true).create_new(true).open(path)?; serde_json::to_writer_pretty(file, value); }",
    ] {
        assert!(!unbuffered_json_writes("sample.rs", example).is_empty(), "{example}");
    }
    for example in [
        "fn sample() { serde_json::to_writer_pretty(&mut writer, value); }",
        "fn sample() { let file = File::create(path)?; serde_json::to_writer(io::stdout().lock(), value); }",
        "fn sample() { let file = File::create(path)?; serde_json::to_writer(&mut stdout, value); }",
        "fn open() { let file = File::create(path)?; }\nfn print() { serde_json::to_writer(writer, value); }",
    ] {
        assert!(unbuffered_json_writes("sample.rs", example).is_empty(), "{example}");
    }
    let buffered = "fn commit() { let file = File::create(path)?; let mut writer = BufWriter::new(file); serde_json::to_writer_pretty(&mut writer, value); writer.flush()?; }";
    assert!(unbuffered_json_writes("processed_index.rs", buffered).is_empty());
    assert!(!unbuffered_json_writes(
        "processed_index.rs",
        &buffered.replace("BufWriter::new(file)", "file")
    )
    .is_empty());
    let append = "fn record_disposition_with_review() { let mut writer = OpenOptions::new().append(true).open(path)?; serde_json::to_writer(&mut writer, value); writer.flush()?; }";
    assert!(unbuffered_json_writes("disposition.rs", append).is_empty());
}

#[test]
fn json_artifacts_use_buffered_writers_or_reviewed_append_paths() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in WalkDir::new(&source).sort_by_file_name() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            let contents = fs::read_to_string(entry.path()).unwrap();
            let relative = entry
                .path()
                .strip_prefix(&source)
                .unwrap()
                .to_str()
                .unwrap();
            let problems = unbuffered_json_writes(relative, &contents);
            assert!(
                problems.is_empty(),
                "{}: {problems:?}",
                entry.path().display()
            );
        }
    }
}
