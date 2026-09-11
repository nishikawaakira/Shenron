//! Lossless private finding storage. Compression does not filter observations.
use anyhow::Context;
use flate2::{read::MultiGzDecoder, write::GzEncoder, Compression};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

/// Resolve a run directory or conventional finding path. Prefer the stored
/// gzip artifact; old runs containing only JSONL remain readable.
pub fn resolve(path: &Path) -> PathBuf {
    if path
        .file_name()
        .is_some_and(|name| name == "private-findings.jsonl.gz")
        && !path.exists()
    {
        return path.with_file_name("private-findings.jsonl");
    }
    let plain = if path.is_dir() {
        path.join("private-findings.jsonl")
    } else {
        path.to_owned()
    };
    if plain
        .file_name()
        .is_some_and(|name| name == "private-findings.jsonl")
    {
        let compressed = plain.with_file_name("private-findings.jsonl.gz");
        if compressed.is_file() {
            return compressed;
        }
    }
    plain
}

pub fn open(path: &Path) -> anyhow::Result<Box<dyn BufRead>> {
    let path = resolve(path);
    let file = File::open(&path)
        .with_context(|| format!("opening private findings {}", path.display()))?;
    if path.extension().is_some_and(|extension| extension == "gz") {
        Ok(Box::new(BufReader::new(MultiGzDecoder::new(
            BufReader::new(file),
        ))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

pub enum FindingSink<'a> {
    Plain(Box<dyn Write + 'a>),
    Gzip(GzEncoder<BufWriter<File>>),
}

impl FindingSink<'_> {
    pub fn compressed(file: File) -> Self {
        // No filename or wall-clock metadata: identical input has stable bytes.
        Self::Gzip(GzEncoder::new(BufWriter::new(file), Compression::default()))
    }
    pub fn finish(self) -> io::Result<()> {
        match self {
            Self::Plain(mut writer) => writer.flush(),
            Self::Gzip(writer) => writer.finish()?.flush(),
        }
    }
}

impl Write for FindingSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(bytes),
            Self::Gzip(writer) => writer.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Gzip(writer) => writer.flush(),
        }
    }
}
