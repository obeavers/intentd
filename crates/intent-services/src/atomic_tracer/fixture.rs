use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use intent_core::{Error, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    association::{invalid, log_digest, GitSourceIdentity, TestObservation},
    digest,
};

pub const SOURCE_PATH: &str = "src/fees.js";
pub const FIXED_TEST_PATH: &str = "test/fees.test.mjs";
pub(crate) const PACKAGE: &str =
    "{\"name\":\"intent-atomic-tracer-fixture\",\"private\":true,\"type\":\"module\"}\n";
pub(crate) const INITIAL_SOURCE: &str = "export function feeCents(amountCents, basisPoints) { return Math.floor(amountCents * basisPoints / 10_000); }\n";
pub(crate) const FIXED_TEST: &str = "import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { feeCents } from '../src/fees.js';\ntest('rounds the fee to the nearest cent', () => { assert.equal(feeCents(1234, 500), 62); });\n";
pub(crate) const TASK_INSTRUCTION: &str =
    "Round the fee to the nearest cent; change only src/fees.js and preserve the test.";
const MAX_OUTPUT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSpec {
    pub title: String,
    pub content: String,
    pub criteria: Vec<String>,
    pub allowed_paths: Vec<String>,
}

impl Default for TaskSpec {
    fn default() -> Self {
        Self {
            title: "Round the fee to the nearest cent".into(),
            content: format!("{TASK_INSTRUCTION}\n\nLeave the source edit uncommitted; the application records the contribution after your turn ends."),
            criteria: vec![
                "feeCents(1234, 500) returns 62.".into(),
                "Only src/fees.js changes; the fixed test and package file remain unchanged."
                    .into(),
            ],
            allowed_paths: vec![SOURCE_PATH.into()],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Fixture {
    pub directory: PathBuf,
    pub(crate) output: Arc<super::DirectoryGuard>,
}

impl Fixture {
    /// Create a new three-file repository fixture; never reuse or reset a project.
    /// # Errors
    /// Refuses an existing fixture directory or a filesystem failure.
    pub fn create(directory: &Path) -> Result<Self> {
        let parent = directory
            .parent()
            .ok_or_else(|| invalid("fixture needs an owned parent"))?;
        Self::create_owned(directory, Arc::new(super::DirectoryGuard::open(parent)?))
    }

    pub(crate) fn create_owned(
        directory: &Path,
        output: Arc<super::DirectoryGuard>,
    ) -> Result<Self> {
        if directory.parent() != Some(output.path()) {
            return Err(invalid("fixture parent differs from owned output"));
        }
        let name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("fixture name must be UTF-8"))?;
        let root = output.create_child(name)?;
        let src = root.create_child("src")?;
        let test = root.create_child("test")?;
        root.write_new("package.json", PACKAGE.as_bytes())?;
        src.write_new("fees.js", INITIAL_SOURCE.as_bytes())?;
        test.write_new("fees.test.mjs", FIXED_TEST.as_bytes())?;
        Ok(Self {
            directory: directory.to_path_buf(),
            output,
        })
    }

    pub(crate) fn validate_fixed_inputs(directory: &Path) -> Result<()> {
        for (path, expected) in [(FIXED_TEST_PATH, FIXED_TEST), ("package.json", PACKAGE)] {
            let file = directory.join(path);
            let metadata = std::fs::symlink_metadata(&file).map_err(|error| io_error(&error))?;
            if !metadata.file_type().is_file()
                || std::fs::read(file).map_err(|error| io_error(&error))? != expected.as_bytes()
            {
                return Err(invalid(format!(
                    "recorded fixed input {path} was modified or replaced"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn add_sentinel(&self, marker: &str) -> Result<()> {
        use std::io::Write as _;
        let path = self.directory.join(SOURCE_PATH);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| io_error(&error))?;
        if !metadata.file_type().is_file() {
            return Err(invalid("working source is no longer a regular file"));
        }
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| io_error(&error))?;
        writeln!(file, "\n// {marker}").map_err(|error| io_error(&error))?;
        file.sync_all().map_err(|error| io_error(&error))
    }
}

pub(crate) fn io_error(error: &std::io::Error) -> Error {
    Error::Internal(format!("Atomic tracer filesystem: {error}"))
}

async fn capture(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| io_error(&error))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(invalid(
            "fixed test output exceeded the retained log budget",
        ));
    }
    Ok(bytes)
}

pub(crate) async fn execute_test(
    directory: &Path,
    source: &GitSourceIdentity,
    node_binary: &Path,
    timeout: Duration,
) -> Result<TestObservation> {
    Fixture::validate_fixed_inputs(directory)?;
    let mut command = tokio::process::Command::new(node_binary);
    command
        .args(["--test", FIXED_TEST_PATH])
        .current_dir(directory)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| Error::Internal(format!("start actual Node fixed test: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("test stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid("test stderr pipe missing"))?;
    // caller-binding: allow — bounded pipe capture never reaches a capability gate.
    let mut stdout = tokio::spawn(capture(stdout));
    // caller-binding: allow — bounded pipe capture never reaches a capability gate.
    let mut stderr = tokio::spawn(capture(stderr));
    let deadline = tokio::time::Instant::now() + timeout;
    let status = if let Ok(result) = tokio::time::timeout_at(deadline, child.wait()).await {
        result.map_err(|error| io_error(&error))?
    } else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        stdout.abort();
        stderr.abort();
        return Err(invalid("actual fixed test exceeded its timeout"));
    };
    let logs = tokio::time::timeout_at(deadline, async {
        let out = (&mut stdout)
            .await
            .map_err(|error| Error::Internal(format!("join test stdout: {error}")))??;
        let err = (&mut stderr)
            .await
            .map_err(|error| Error::Internal(format!("join test stderr: {error}")))??;
        Ok::<_, Error>((out, err))
    })
    .await;
    let (stdout, stderr) = if let Ok(result) = logs {
        result?
    } else {
        stdout.abort();
        stderr.abort();
        return Err(invalid("fixed test log drain exceeded its timeout"));
    };
    let stdout = String::from_utf8(stdout).map_err(|_| invalid("test stdout was not UTF-8"))?;
    let stderr = String::from_utf8(stderr).map_err(|_| invalid("test stderr was not UTF-8"))?;
    let exit_code = status
        .code()
        .ok_or_else(|| invalid("fixed test exited by signal"))?;
    Ok(TestObservation {
        command: vec![
            node_binary.to_string_lossy().into_owned(),
            "--test".into(),
            FIXED_TEST_PATH.into(),
        ],
        exit_code,
        log_digest: log_digest(&stdout, &stderr)?,
        stdout,
        stderr,
        source: source.clone(),
        fixed_test_digest: digest(FIXED_TEST.as_bytes()),
        package_digest: digest(PACKAGE.as_bytes()),
    })
}
