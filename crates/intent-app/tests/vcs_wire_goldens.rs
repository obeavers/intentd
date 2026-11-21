//! Wire goldens for the VCS surface: every `git.*`, `gitRoot.*`,
//! `accept-changes.*` and `file-tracking.*` response on a Git workspace,
//! captured byte-for-byte so a refactor of the VCS seam can prove it changed
//! nothing on the wire (atomic-substrate adoption plan, §15 V1).
//!
//! # Methods
//!
//! The method set is derived from `intent_transport::catalog::ROUTER_METHODS`
//! (filtered by the four namespaces) and `every_vcs_method_has_a_case`
//! asserts the case table covers exactly that set, so a new method fails
//! here until it gets a golden. Today's 41 dispatched methods:
//!
//! - `git.*` (28): agentCommit, branchDiff, branchStatus, changes,
//!   checkMergeConflicts, checkoutBranch, clone, commitDetails, commits,
//!   createBranch, diffs, discard, fetch, getBranches, getConfig,
//!   getRemoteUrl, numstat, pull, push, removeLockFile, renameBranch,
//!   showFile, showFileChunk, stage, stageHunk, status, unstage, unstageHunk
//! - `gitRoot.*` (1): list
//! - `accept-changes.*` (7): addRemote, execute, getStatus, mergePR,
//!   prepare, reconcile, release
//! - `file-tracking.*` (5): getAgentLocks, getChanges, loadCommits, stage,
//!   unstage
//!
//! Retired names whose rejection is pinned too ([`RETIRED`]): `git.commit`
//! (removed in protocol 13.0), `git.diff`, `git.log` and
//! `file-tracking.getLineStats`. Names in the protocol docs that are not
//! wire methods and so have no golden: `git.autoCommit` (a setting key),
//! `ws.git.registerRoot` / `unregisterRoot` / `listRoots` (MCP-only), and
//! `accept-changes.retired` (a server notification, not a request).
//!
//! # Harness
//!
//! Each case gets a fresh fixture: deterministic Git repositories (fixed
//! author, committer and dates, fixed contents, a bare `origin` it was
//! pushed to), a fresh `SQLite` store with one workspace over the repo, and
//! the composed services (`intent_app::compose`) served by the real UDS
//! listener (`intent_transport::serve_uds`). The request goes over a real
//! socket and the golden is the raw response line exactly as it left the
//! daemon, so the router, the connection's gates and the serializer are all
//! inside the comparison. This mirrors `payload_budget/harness.rs`, whose
//! client cannot be imported (it depends on that suite's `rows` / `seed` /
//! `proxies` modules).
//!
//! # Determinism
//!
//! `main` sets a hermetic process environment once, before any thread or
//! Git process starts (`HOME`, `XDG_CONFIG_HOME`, `GIT_CONFIG_GLOBAL`,
//! `GIT_CONFIG_NOSYSTEM`, `TZ`, `LC_ALL`), so the developer's Git config
//! cannot leak in. That is why every case runs sequentially inside one
//! plain `#[test]` and this file is its own test target. The only
//! normalisation is [`redact`]; see its docs for the exact rules.
//!
//! # Updating
//!
//! `UPDATE_GOLDENS=1 cargo test -p intent-app --test vcs_wire_goldens`
//! rewrites every golden and `COVERAGE.md`. Without it a missing, changed
//! or orphaned golden fails the test.
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use intent_core::{Workspace, WorkspaceId};
use intent_services::{EventBus, Services};
use intent_store::Store;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const NAMESPACES: &[&str] = &["git.", "gitRoot.", "accept-changes.", "file-tracking."];

/// Names that are no longer dispatched; their rejection is pinned.
const RETIRED: &[&str] = &[
    "git.commit",
    "git.diff",
    "git.log",
    "file-tracking.getLineStats",
];

/// Methods whose success path needs something a local fixture cannot
/// provide, with the reason. They still have error-path goldens.
const ERROR_ONLY: &[(&str, &str)] = &[
    (
        "accept-changes.mergePR",
        "merges a pull request on the forge; needs a GitHub repository and credentials",
    ),
    (
        "accept-changes.reconcile",
        "replays a native-review attempt; a real attempt needs a forge review target \
         (`accept-changes.prepare` with `review` resolves the target on the forge)",
    ),
    (
        "accept-changes.release",
        "retires a native-review attempt; same forge prerequisite as reconcile",
    ),
];

const WS: &str = "ws-golden";
const CREATED_AT: &str = "2026-01-01T00:00:00Z";
/// Fixture commit time: 2026-01-01T00:00:00Z.
const T0: i64 = 1_767_225_600;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/vcs_wire")
}

fn updating() -> bool {
    std::env::var_os("UPDATE_GOLDENS").is_some_and(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// Fixture repositories
// ---------------------------------------------------------------------------

/// Working-tree state on top of the shared history.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tree {
    /// Committed history only.
    Clean,
    /// Every kind of local change at once (see [`dirty`]).
    Dirty,
}

/// One case's fixture: the repositories, the store and the daemon.
struct Fx {
    _dir: tempfile::TempDir,
    /// Canonical fixture root; every path below lives under it.
    root: PathBuf,
    /// The workspace worktree.
    repo: PathBuf,
    /// Bare remote the history was pushed to (`origin`).
    origin: PathBuf,
    /// An existing directory that is not a Git repository.
    plain: PathBuf,
    /// Fixture commit SHAs by name (`c1`, `c2`, `c3`, `side`).
    sha: BTreeMap<&'static str, String>,
    /// Every commit reachable in the fixture before the call.
    commits_before: BTreeSet<String>,
    /// `git diff README.md` of the dirty tree (an unstaged hunk).
    readme_patch: String,
    /// `git diff --cached both.txt` of the dirty tree (a staged hunk).
    both_staged_patch: String,
    socket: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Fx {
    fn repo_s(&self) -> String {
        self.repo.display().to_string()
    }
    fn sha(&self, name: &str) -> String {
        self.sha[name].clone()
    }
}

/// Run git in `dir` with a fixed identity and, for commits, a fixed date.
#[track_caller]
fn git_at(dir: &Path, args: &[&str], date: Option<i64>) -> String {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Golden Author")
        .env("GIT_AUTHOR_EMAIL", "author@golden.invalid")
        .env("GIT_COMMITTER_NAME", "Golden Committer")
        .env("GIT_COMMITTER_EMAIL", "committer@golden.invalid");
    if let Some(t) = date {
        let stamp = format!("@{t} +0000");
        cmd.env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp);
    }
    let out = cmd.output().expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("git output is UTF-8")
}

#[track_caller]
fn git(dir: &Path, args: &[&str]) -> String {
    git_at(dir, args, None)
}

#[track_caller]
fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, bytes).expect("write");
}

#[track_caller]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

const LOGO_V1: &[u8] = &[0x89, b'P', b'N', b'G', 0, 0, 0, 1, 0xff, 0xfe, 0, 7];
const LOGO_V2: &[u8] = &[0x89, b'P', b'N', b'G', 0, 0, 0, 2, 0xff, 0xfe, 0, 9, 0];

/// Three commits on `main` (the first two pushed to `origin`), one on
/// `feature/side`, branched from the second.
fn history(repo: &Path, origin: &Path) -> BTreeMap<&'static str, String> {
    git(origin, &["init", "--bare", "--quiet", "-b", "main"]);
    git(repo, &["init", "--quiet", "-b", "main"]);
    for (k, v) in [
        ("user.name", "Golden Daemon"),
        ("user.email", "daemon@golden.invalid"),
        ("core.fileMode", "true"),
        ("core.autocrlf", "false"),
        ("commit.gpgSign", "false"),
    ] {
        git(repo, &["config", k, v]);
    }
    git(
        repo,
        &["remote", "add", "origin", origin.to_str().expect("utf8")],
    );
    let mut sha = BTreeMap::new();

    write(&repo.join("README.md"), b"# Golden fixture\n\nIntro.\n");
    write(
        &repo.join("src/lib.rs"),
        b"pub fn one() -> u32 {\n    1\n}\n",
    );
    write(
        &repo.join("docs/guide.md"),
        b"# Guide\n\nStep one.\nStep two.\nStep three.\nStep four.\n",
    );
    write(&repo.join("both.txt"), b"alpha\nbeta\ngamma\n");
    write(&repo.join("delete-me.txt"), b"remove me\n");
    write(&repo.join("assets/logo.bin"), LOGO_V1);
    write(&repo.join("run.sh"), b"#!/bin/sh\necho golden\n");
    chmod(&repo.join("run.sh"), 0o644);
    git(repo, &["add", "-A"]);
    git_at(
        repo,
        &["commit", "--quiet", "-m", "Initial commit"],
        Some(T0),
    );
    sha.insert("c1", git(repo, &["rev-parse", "HEAD"]).trim().to_string());

    write(
        &repo.join("src/lib.rs"),
        b"pub fn one() -> u32 {\n    1\n}\n\npub fn two() -> u32 {\n    2\n}\n",
    );
    git(repo, &["add", "-A"]);
    git_at(
        repo,
        &[
            "commit",
            "--quiet",
            "-m",
            "Add two()\n\nSecond commit body.",
        ],
        Some(T0 + 60),
    );
    sha.insert("c2", git(repo, &["rev-parse", "HEAD"]).trim().to_string());
    git(repo, &["push", "--quiet", "-u", "origin", "main"]);

    git(repo, &["checkout", "--quiet", "-b", "feature/side"]);
    write(&repo.join("side.txt"), b"side branch\n");
    git(repo, &["add", "-A"]);
    git_at(
        repo,
        &["commit", "--quiet", "-m", "Side change"],
        Some(T0 + 180),
    );
    sha.insert("side", git(repo, &["rev-parse", "HEAD"]).trim().to_string());
    git(repo, &["checkout", "--quiet", "main"]);

    write(
        &repo.join("README.md"),
        b"# Golden fixture\n\nIntro, revised.\n",
    );
    git(repo, &["add", "-A"]);
    git_at(
        repo,
        &["commit", "--quiet", "-m", "Update readme"],
        Some(T0 + 120),
    );
    sha.insert("c3", git(repo, &["rev-parse", "HEAD"]).trim().to_string());
    sha
}

/// Modified, staged + unstaged on one file, untracked, deleted, renamed,
/// binary and executable-bit changes, all at once.
fn dirty(repo: &Path) {
    write(
        &repo.join("README.md"),
        b"# Golden fixture\n\nIntro, revised.\nDirty line.\n",
    );
    write(&repo.join("both.txt"), b"alpha\nBETA\ngamma\n");
    git(repo, &["add", "both.txt"]);
    write(&repo.join("both.txt"), b"alpha\nBETA\nGAMMA\n");
    write(&repo.join("notes/new.txt"), b"brand new\n");
    std::fs::remove_file(repo.join("delete-me.txt")).expect("delete");
    git(repo, &["mv", "docs/guide.md", "docs/manual.md"]);
    write(&repo.join("assets/logo.bin"), LOGO_V2);
    chmod(&repo.join("run.sh"), 0o755);
}

fn all_commits(repo: &Path) -> BTreeSet<String> {
    git(repo, &["rev-list", "--all"])
        .lines()
        .map(str::to_string)
        .collect()
}

/// Hermetic process environment; called once, before any thread starts.
fn hermetic_env(home: &Path) {
    let gitconfig = home.join("gitconfig");
    std::fs::write(&gitconfig, "").expect("empty global gitconfig");
    // process-global: allow — runs once in this file's single test, before the runtime or any child exists
    std::env::set_var("HOME", home);
    std::env::set_var("XDG_CONFIG_HOME", home.join("xdg"));
    std::env::set_var("GIT_CONFIG_GLOBAL", &gitconfig);
    std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
    std::env::set_var("TZ", "UTC");
    std::env::set_var("LC_ALL", "C");
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_DATE",
    ] {
        std::env::remove_var(key);
    }
}

/// Everything built once and copied per case: the migrated store and one
/// copy of the repositories per [`Tree`]. Building the fixture history
/// spawns ~30 git processes, so rebuilding it per case would dominate the
/// suite's runtime.
struct Templates {
    _dir: tempfile::TempDir,
    db: PathBuf,
    clean: PathBuf,
    dirty: PathBuf,
    sha: BTreeMap<&'static str, String>,
    readme_patch: String,
    both_staged_patch: String,
}

impl Templates {
    async fn build() -> Self {
        let dir = intent_services::test_support::test_tempdir("itd-vcs-template-");
        let base = std::fs::canonicalize(dir.path()).expect("canonical template dir");
        let db = base.join("template.db");
        let store = Store::open(&db).await.expect("open template store");
        // Checkpoints the WAL so the single file is the whole database.
        store.close().await;
        drop(store);
        let mut sha = BTreeMap::new();
        let mut patches = (String::new(), String::new());
        for tree in [Tree::Clean, Tree::Dirty] {
            let root = base.join(tree.dir());
            let (repo, origin) = (root.join("repo"), root.join("origin.git"));
            for d in [&repo, &origin, &root.join("plain")] {
                std::fs::create_dir_all(d).expect("mkdir");
            }
            sha = history(&repo, &origin);
            if tree == Tree::Dirty {
                dirty(&repo);
                patches = (
                    git(&repo, &["diff", "README.md"]),
                    git(&repo, &["diff", "--cached", "both.txt"]),
                );
            }
        }
        Self {
            clean: base.join(Tree::Clean.dir()),
            dirty: base.join(Tree::Dirty.dir()),
            _dir: dir,
            db,
            sha,
            readme_patch: patches.0,
            both_staged_patch: patches.1,
        }
    }
}

impl Tree {
    fn dir(self) -> &'static str {
        match self {
            Tree::Clean => "clean",
            Tree::Dirty => "dirty",
        }
    }
}

/// Recursive copy that keeps file modes (the executable-bit fixture).
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read template dir") {
        let entry = entry.expect("template entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy template file");
        }
    }
}

/// Copy the templates into a fresh root and start a daemon over them.
async fn fixture(tpl: &Templates, tree: Tree, prep: Option<fn(&Fx)>) -> Fx {
    // Short root: the UDS socket lives here too (macOS caps socket paths).
    let dir = intent_services::test_support::test_tempdir_in("/tmp", "itd-vcs-");
    let root = std::fs::canonicalize(dir.path()).expect("canonical root");
    copy_tree(
        match tree {
            Tree::Clean => &tpl.clean,
            Tree::Dirty => &tpl.dirty,
        },
        &root,
    );
    let repo = root.join("repo");
    let origin = root.join("origin.git");
    let plain = root.join("plain");
    // The only path-bearing setting in the copied repositories.
    git(
        &repo,
        &[
            "config",
            "remote.origin.url",
            origin.to_str().expect("utf8"),
        ],
    );
    let sha = tpl.sha.clone();
    let (readme_patch, both_staged_patch) = if tree == Tree::Dirty {
        (tpl.readme_patch.clone(), tpl.both_staged_patch.clone())
    } else {
        (String::new(), String::new())
    };

    // A copy of the migrated template: running every migration per case
    // costs seconds in debug builds.
    let db = root.join("intentd.db");
    std::fs::copy(&tpl.db, &db).expect("copy template db");
    let store = Store::open(&db).await.expect("open store");
    store
        .insert_workspace(&Workspace {
            id: WorkspaceId::from(WS),
            title: "Golden".to_string(),
            branch: "main".to_string(),
            base_ref: Some("origin/main".to_string()),
            worktree_path: Some(repo.display().to_string()),
            repository_path: Some(repo.display().to_string()),
            created_at: CREATED_AT.to_string(),
            updated_at: CREATED_AT.to_string(),
            ..Default::default()
        })
        .await
        .expect("insert workspace");
    let bus = EventBus::new(store.clone());
    let services = intent_app::compose(Services::new_isolated(store))
        .with_workspaces_root(root.join("workspaces"))
        .with_assets_root(root.join("assets"))
        .with_event_bus(bus.clone());
    let socket = root.join("s.sock");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let api: Arc<dyn intent_core::WorkspaceApi> = Arc::new(services);
    intent_core::spawn_daemon({
        let socket = socket.clone();
        async move {
            let _ = intent_transport::serve_uds(api, bus, &socket, None, async {
                let _ = rx.await;
            })
            .await;
        }
    });
    let mut fx = Fx {
        _dir: dir,
        root,
        repo,
        origin,
        plain,
        sha,
        commits_before: BTreeSet::new(),
        readme_patch,
        both_staged_patch,
        socket,
        shutdown: Some(tx),
    };
    if let Some(prep) = prep {
        prep(&fx);
    }
    fx.commits_before = all_commits(&fx.repo);
    fx
}

// ---------------------------------------------------------------------------
// Wire client
// ---------------------------------------------------------------------------

fn frame_timeout() -> Duration {
    intentd_test_support::test_timeout(Duration::from_secs(60))
}

/// One raw JSON-RPC connection.
struct Client {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl Client {
    async fn connect(socket: &Path) -> Self {
        let mut last = None;
        for _ in 0..500 {
            match UnixStream::connect(socket).await {
                Ok(stream) => {
                    let (read, writer) = stream.into_split();
                    return Self {
                        reader: BufReader::new(read),
                        writer,
                    };
                }
                Err(e) => last = Some(e),
            }
            // timing-guard: retry interval while the listener binds its socket; there is no bind event to await
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("connect {}: {last:?}", socket.display());
    }

    /// Send one request with id `id`; return the raw response line exactly
    /// as received (without the newline), skipping notifications.
    async fn call(&mut self, id: u64, method: &str, params: &Value) -> String {
        let frame = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let mut raw = frame.to_string();
        raw.push('\n');
        self.writer.write_all(raw.as_bytes()).await.expect("write");
        self.writer.flush().await.expect("flush");
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(frame_timeout(), self.reader.read_line(&mut line))
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {method}"))
                .expect("read frame");
            assert!(n > 0, "connection closed during {method}");
            let line = line.trim_end_matches('\n').to_string();
            let parsed: Value = serde_json::from_str(&line).expect("frame is JSON");
            if parsed.get("id") == Some(&json!(id)) {
                return line;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// The single normalisation applied to a response line before it is
/// compared. Everything not listed here must match byte-for-byte.
///
/// 1. **Fixture root.** The case's temp directory (canonical form, and the
///    `/tmp` → `/private/tmp` alias on macOS) becomes `<ROOT>`.
/// 2. **Daemon-made commits.** A commit the daemon creates during the call
///    is stamped with the wall clock (`repo.signature()`), so its SHA is
///    not reproducible. Each 40-hex SHA of a commit that exists after the
///    call but did not before becomes `<NEW-COMMIT-n>` (numbered by first
///    appearance), and any 7+ hex prefix of it becomes
///    `<NEW-COMMIT-n-SHORT>`. Fixture commit SHAs and every other object
///    id are fixed by construction and are kept verbatim.
/// 3. **Generated UUIDs** (`8-4-4-4-12` hex) become `<UUID-n>`.
/// 4. **Wall-clock times.** An ISO-8601 timestamp outside the fixture's
///    year (2026-01-01 .. 2026-01-02, the only times the fixture writes)
///    becomes `<NOW>`, and a 10- or 13-digit epoch number at or after the
///    fixture's last commit plus one day becomes `<NOW-EPOCH>`.
fn redact(raw: &str, fx: &Fx) -> String {
    let mut out = raw.to_string();
    let root = fx.root.display().to_string();
    let mut roots = vec![root.clone()];
    if let Some(rest) = root.strip_prefix("/private") {
        roots.push(rest.to_string());
    }
    roots.sort_by_key(|r| std::cmp::Reverse(r.len()));
    for r in &roots {
        out = out.replace(r.as_str(), "<ROOT>");
    }

    let new_commits: Vec<String> = all_commits(&fx.repo)
        .difference(&fx.commits_before)
        .cloned()
        .collect();
    out = redact_new_commits(&out, &new_commits);
    out = redact_uuids(&out);
    redact_times(&out)
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Replace maximal `[0-9a-f]` runs (bounded by non-alphanumerics) with
/// `f(run)` when it returns `Some`.
fn replace_hex_runs(s: &str, mut f: impl FnMut(&str) -> Option<String>) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if boundary && is_hex(bytes[i]) {
            let mut j = i;
            while j < bytes.len() && is_hex(bytes[j]) {
                j += 1;
            }
            let end_ok = j == bytes.len() || !bytes[j].is_ascii_alphanumeric();
            if end_ok {
                if let Some(rep) = f(&s[i..j]) {
                    out.push_str(&rep);
                    i = j;
                    continue;
                }
            }
            out.push_str(&s[i..j]);
            i = j;
            continue;
        }
        out.push(s[i..].chars().next().expect("char"));
        i += s[i..].chars().next().expect("char").len_utf8();
    }
    out
}

fn redact_new_commits(s: &str, new_commits: &[String]) -> String {
    if new_commits.is_empty() {
        return s.to_string();
    }
    let mut order: Vec<String> = Vec::new();
    // Number by first full-SHA appearance; a prefix seen first still maps.
    let index_of = |sha: &str, order: &mut Vec<String>| -> usize {
        if let Some(i) = order.iter().position(|o| o == sha) {
            return i + 1;
        }
        order.push(sha.to_string());
        order.len()
    };
    replace_hex_runs(s, |run| {
        if run.len() == 40 && new_commits.iter().any(|c| c == run) {
            let n = index_of(run, &mut order);
            return Some(format!("<NEW-COMMIT-{n}>"));
        }
        if (7..40).contains(&run.len()) {
            let hits: Vec<&String> = new_commits.iter().filter(|c| c.starts_with(run)).collect();
            if let [only] = hits.as_slice() {
                let n = index_of(only, &mut order);
                return Some(format!("<NEW-COMMIT-{n}-SHORT>"));
            }
        }
        None
    })
}

fn redact_uuids(input: &str) -> String {
    let bytes = input.as_bytes();
    let groups = [8usize, 4, 4, 4, 12];
    let mut seen: Vec<String> = Vec::new();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    'scan: while cursor < bytes.len() {
        let boundary = cursor == 0 || !bytes[cursor - 1].is_ascii_alphanumeric();
        if boundary {
            let mut end = cursor;
            let mut valid = true;
            for (group, len) in groups.iter().enumerate() {
                if group > 0 {
                    if bytes.get(end) != Some(&b'-') {
                        valid = false;
                        break;
                    }
                    end += 1;
                }
                for _ in 0..*len {
                    if !bytes.get(end).copied().is_some_and(is_hex) {
                        valid = false;
                        break;
                    }
                    end += 1;
                }
                if !valid {
                    break;
                }
            }
            if valid && (end == bytes.len() || !bytes[end].is_ascii_alphanumeric()) {
                let uuid = &input[cursor..end];
                let number =
                    if let Some(position) = seen.iter().position(|seen_uuid| seen_uuid == uuid) {
                        position + 1
                    } else {
                        seen.push(uuid.to_string());
                        seen.len()
                    };
                write!(out, "<UUID-{number}>").expect("format UUID redaction");
                cursor = end;
                continue 'scan;
            }
        }
        let ch = input[cursor..].chars().next().expect("char");
        out.push(ch);
        cursor += ch.len_utf8();
    }
    out
}

/// ISO timestamps outside the fixture window and epoch numbers past it.
fn redact_times(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let digit = |k: usize| bytes.get(k).is_some_and(u8::is_ascii_digit);
    while i < bytes.len() {
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        // YYYY-MM-DDTHH:MM:SS[.fff][Z|+HH:MM]
        let iso = boundary
            && (0..4).all(|k| digit(i + k))
            && bytes.get(i + 4) == Some(&b'-')
            && digit(i + 5)
            && digit(i + 6)
            && bytes.get(i + 7) == Some(&b'-')
            && digit(i + 8)
            && digit(i + 9)
            && bytes.get(i + 10) == Some(&b'T')
            && digit(i + 11)
            && digit(i + 12)
            && bytes.get(i + 13) == Some(&b':');
        if iso {
            let mut j = i + 11;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit()
                    || matches!(bytes[j], b':' | b'.' | b'+' | b'-' | b'Z'))
            {
                j += 1;
            }
            let stamp = &s[i..j];
            if stamp.starts_with("2026-01-01") || stamp.starts_with("2026-01-02") {
                out.push_str(stamp);
            } else {
                out.push_str("<NOW>");
            }
            i = j;
            continue;
        }
        if boundary && digit(i) {
            let mut j = i;
            while digit(j) {
                j += 1;
            }
            let end_ok = j == bytes.len() || !bytes[j].is_ascii_alphanumeric();
            let num = &s[i..j];
            let limit_secs = T0 + 86_400;
            let wall = end_ok
                && match num.len() {
                    10 => num.parse::<i64>().is_ok_and(|n| n >= limit_secs),
                    13 => num.parse::<i64>().is_ok_and(|n| n >= limit_secs * 1000),
                    _ => false,
                };
            out.push_str(if wall { "<NOW-EPOCH>" } else { num });
            i = j;
            continue;
        }
        let ch = s[i..].chars().next().expect("char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

type Params = fn(&Fx) -> Value;

struct Case {
    method: &'static str,
    name: &'static str,
    tree: Tree,
    /// Extra fixture setup run after the tree is built.
    prep: Option<fn(&Fx)>,
    params: Params,
    /// Read-back after a mutation, goldened as `<method>__<name>__after`.
    after: Option<(&'static str, Params)>,
}

const fn case(method: &'static str, name: &'static str, tree: Tree, params: Params) -> Case {
    Case {
        method,
        name,
        tree,
        prep: None,
        params,
        after: None,
    }
}

impl Case {
    const fn after(mut self, method: &'static str, params: Params) -> Self {
        self.after = Some((method, params));
        self
    }
    const fn prep(mut self, prep: fn(&Fx)) -> Self {
        self.prep = Some(prep);
        self
    }
}

fn ws(_: &Fx) -> Value {
    json!({ "workspaceId": WS })
}
fn none(_: &Fx) -> Value {
    json!({})
}
fn unknown_ws(_: &Fx) -> Value {
    json!({ "workspaceId": "ws-missing" })
}
fn status(_: &Fx) -> Value {
    json!({ "workspaceId": WS, "forceRefresh": true })
}
fn commits_after(_: &Fx) -> Value {
    json!({ "workspaceId": WS, "limit": 10 })
}
fn branches_after(fx: &Fx) -> Value {
    json!({ "repoPath": fx.repo_s(), "includeRemote": true })
}
fn accept_status_after(_: &Fx) -> Value {
    json!({ "workspaceId": WS })
}

use Tree::{Clean, Dirty};

#[expect(
    clippy::too_many_lines,
    reason = "one flat table is easier to audit than split helpers"
)]
fn cases() -> Vec<Case> {
    vec![
        // ---- git.status -------------------------------------------------
        case("git.status", "dirty", Dirty, ws),
        case("git.status", "clean", Clean, ws),
        case("git.status", "force_refresh", Dirty, status),
        case("git.status", "missing_workspace_id", Dirty, none),
        case("git.status", "unknown_workspace", Dirty, unknown_ws),
        case("git.status", "unknown_git_root", Dirty, |_| {
            json!({ "workspaceId": WS, "gitRootId": "root-missing" })
        }),
        // ---- gitRoot.list -----------------------------------------------
        case("gitRoot.list", "no_roots", Dirty, ws),
        case("gitRoot.list", "unknown_workspace", Dirty, unknown_ws),
        // ---- git.getConfig ----------------------------------------------
        case("git.getConfig", "dirty", Dirty, ws),
        case("git.getConfig", "missing_workspace_id", Dirty, none),
        // ---- git.stage --------------------------------------------------
        case("git.stage", "array", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["both.txt", "notes/new.txt", "README.md"] })
        })
        .after("git.status", status),
        case("git.stage", "csv", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": "delete-me.txt,run.sh,assets/logo.bin" })
        })
        .after("git.status", status),
        case("git.stage", "reject_all", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["."] })
        }),
        case("git.stage", "no_such_path", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["does/not/exist.txt"] })
        }),
        case("git.stage", "missing_paths", Dirty, ws),
        // ---- git.unstage ------------------------------------------------
        case("git.unstage", "staged_file", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["both.txt"] })
        })
        .after("git.status", status),
        case("git.unstage", "rename", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["docs/manual.md", "docs/guide.md"] })
        })
        .after("git.status", status),
        case("git.unstage", "missing_paths", Dirty, ws),
        // ---- git.discard ------------------------------------------------
        case("git.discard", "modified", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["README.md", "assets/logo.bin"] })
        })
        .after("git.status", status),
        case("git.discard", "deleted_and_untracked", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["delete-me.txt", "notes/new.txt"] })
        })
        .after("git.status", status),
        case("git.discard", "missing_paths", Dirty, ws),
        // ---- git.stageHunk / git.unstageHunk ----------------------------
        case("git.stageHunk", "readme", Dirty, |fx| {
            json!({ "workspaceId": WS, "filePath": "README.md", "hunkPatch": fx.readme_patch })
        })
        .after("git.status", status),
        case("git.stageHunk", "wrong_file", Dirty, |fx| {
            json!({ "workspaceId": WS, "filePath": "both.txt", "hunkPatch": fx.readme_patch })
        }),
        case("git.stageHunk", "missing_patch", Dirty, |_| {
            json!({ "workspaceId": WS, "filePath": "README.md" })
        }),
        case("git.unstageHunk", "both", Dirty, |fx| {
            json!({ "workspaceId": WS, "filePath": "both.txt", "hunkPatch": fx.both_staged_patch })
        })
        .after("git.status", status),
        case("git.unstageHunk", "not_staged", Dirty, |fx| {
            json!({ "workspaceId": WS, "filePath": "README.md", "hunkPatch": fx.readme_patch })
        }),
        // ---- git.push / git.fetch / git.pull -----------------------------
        case("git.push", "ahead_one", Clean, ws).after("git.status", status),
        case("git.push", "force", Clean, |_| {
            json!({ "workspaceId": WS, "force": true })
        })
        .after("git.status", status),
        case("git.push", "missing_workspace_id", Clean, none),
        case("git.fetch", "origin", Clean, ws).after("git.status", status),
        case("git.fetch", "unknown_workspace", Clean, unknown_ws),
        case("git.pull", "up_to_date", Clean, |fx| {
            json!({ "repoPath": fx.repo_s(), "branchName": "main" })
        })
        .after("git.status", status),
        case("git.pull", "behind_origin", Clean, |fx| {
            json!({ "repoPath": fx.repo_s(), "branchName": "main" })
        })
        .prep(|fx| {
            // Rewind main to c1 so origin/main (c2) is one ahead.
            git(&fx.repo, &["reset", "--quiet", "--hard", &fx.sha("c1")]);
        })
        .after("git.status", status),
        case("git.pull", "dirty_conflict", Dirty, |fx| {
            json!({ "repoPath": fx.repo_s(), "branchName": "main" })
        }),
        case("git.pull", "missing_path", Clean, |fx| {
            json!({ "repoPath": fx.root.join("nope").display().to_string(), "branchName": "main" })
        }),
        case("git.pull", "not_a_repo", Clean, |fx| {
            json!({ "repoPath": fx.plain.display().to_string(), "branchName": "main" })
        }),
        case("git.pull", "missing_branch_name", Clean, |fx| {
            json!({ "repoPath": fx.repo_s() })
        }),
        // ---- branches -----------------------------------------------------
        case("git.createBranch", "checkout", Clean, |_| {
            json!({ "workspaceId": WS, "branchName": "feature/new" })
        })
        .after("git.getBranches", branches_after),
        case("git.createBranch", "no_checkout", Clean, |_| {
            json!({ "workspaceId": WS, "branchName": "feature/new", "checkout": false })
        })
        .after("git.getBranches", branches_after),
        case("git.createBranch", "exists", Clean, |_| {
            json!({ "workspaceId": WS, "branchName": "feature/side" })
        }),
        case("git.createBranch", "missing_name", Clean, ws),
        case("git.checkoutBranch", "side", Clean, |_| {
            json!({ "workspaceId": WS, "branchName": "feature/side" })
        })
        .after("git.status", status),
        case("git.checkoutBranch", "no_such_branch", Clean, |_| {
            json!({ "workspaceId": WS, "branchName": "feature/missing" })
        }),
        case("git.renameBranch", "side", Clean, |_| {
            json!({ "workspaceId": WS, "oldBranchName": "feature/side", "newBranchName": "feature/renamed" })
        })
        .after("git.getBranches", branches_after),
        case("git.renameBranch", "no_such_branch", Clean, |_| {
            json!({ "workspaceId": WS, "oldBranchName": "feature/missing", "newBranchName": "x" })
        }),
        case("git.renameBranch", "missing_new_name", Clean, |_| {
            json!({ "workspaceId": WS, "oldBranchName": "feature/side" })
        }),
        case("git.removeLockFile", "no_lock", Clean, ws),
        case("git.removeLockFile", "stale_lock", Clean, ws)
            .prep(|fx| write(&fx.repo.join(".git/index.lock"), b""))
            .after("git.status", status),
        case("git.getBranches", "local", Clean, |fx| {
            json!({ "repoPath": fx.repo_s() })
        }),
        case("git.getBranches", "include_remote", Dirty, branches_after),
        case("git.getBranches", "with_workspace_id", Clean, |fx| {
            json!({ "repoPath": fx.repo_s(), "includeRemote": true, "workspaceId": WS })
        }),
        case("git.getBranches", "missing_path", Clean, |fx| {
            json!({ "repoPath": fx.root.join("nope").display().to_string() })
        }),
        case("git.getBranches", "not_a_repo", Clean, |fx| {
            json!({ "repoPath": fx.plain.display().to_string() })
        }),
        case("git.getBranches", "missing_repo_path", Clean, none),
        case("git.branchStatus", "main", Clean, |fx| {
            json!({ "repoPath": fx.repo_s(), "branchName": "main" })
        }),
        case("git.branchStatus", "side", Dirty, |fx| {
            json!({ "repoPath": fx.repo_s(), "branchName": "feature/side" })
        }),
        case("git.branchStatus", "no_such_branch", Clean, |fx| {
            json!({ "repoPath": fx.repo_s(), "branchName": "feature/missing" })
        }),
        case("git.branchStatus", "unknown_git_root", Clean, |_| {
            json!({ "workspaceId": WS, "gitRootId": "root-missing", "branchName": "main" })
        }),
        case("git.branchStatus", "missing_path", Clean, |fx| {
            json!({ "repoPath": fx.root.join("nope").display().to_string(), "branchName": "main" })
        }),
        case("git.branchStatus", "not_a_repo", Clean, |fx| {
            json!({ "repoPath": fx.plain.display().to_string(), "branchName": "main" })
        }),
        case("git.branchStatus", "missing_repo_path", Clean, |_| {
            json!({ "branchName": "main" })
        }),
        // ---- git.clone ----------------------------------------------------
        case("git.clone", "local_origin", Clean, |fx| {
            json!({
                "url": fx.origin.display().to_string(),
                "parentDir": fx.root.join("clones").display().to_string(),
                "targetName": "copy",
            })
        })
        .prep(|fx| std::fs::create_dir_all(fx.root.join("clones")).expect("clones dir")),
        case("git.clone", "missing_source", Clean, |fx| {
            json!({
                "url": fx.root.join("no-such-origin.git").display().to_string(),
                "parentDir": fx.root.join("clones").display().to_string(),
                "targetName": "copy",
            })
        })
        .prep(|fx| std::fs::create_dir_all(fx.root.join("clones")).expect("clones dir")),
        case("git.clone", "target_exists", Clean, |fx| {
            json!({
                "url": fx.origin.display().to_string(),
                "parentDir": fx.root.display().to_string(),
                "targetName": "repo",
            })
        }),
        case("git.clone", "missing_url", Clean, |fx| {
            json!({ "parentDir": fx.root.display().to_string() })
        }),
        // ---- git.agentCommit ---------------------------------------------
        case("git.agentCommit", "files", Dirty, |_| {
            json!({
                "workspaceId": WS,
                "message": "Commit README and new note",
                "files": ["README.md", "notes/new.txt"],
                "userRequested": true,
            })
        })
        .after("git.commits", commits_after),
        case("git.agentCommit", "staged_index", Dirty, |_| {
            json!({ "workspaceId": WS, "message": "Commit the index", "userRequested": true })
        })
        .after("git.status", status),
        case("git.agentCommit", "nothing_to_commit", Clean, |_| {
            json!({ "workspaceId": WS, "message": "Empty", "userRequested": true })
        }),
        case("git.agentCommit", "missing_message", Dirty, ws),
        case("git.agentCommit", "unknown_git_root", Dirty, |_| {
            json!({ "workspaceId": WS, "message": "m", "userRequested": true, "gitRootId": "root-missing" })
        }),
        // ---- git.checkMergeConflicts --------------------------------------
        case("git.checkMergeConflicts", "default_target", Clean, ws),
        case("git.checkMergeConflicts", "side", Clean, |_| {
            json!({ "workspaceId": WS, "targetBranch": "feature/side" })
        }),
        case("git.checkMergeConflicts", "conflicting", Clean, |_| {
            json!({ "workspaceId": WS, "targetBranch": "feature/conflict" })
        })
        .prep(|fx| {
            git(&fx.repo, &["checkout", "--quiet", "-b", "feature/conflict", &fx.sha("c2")]);
            write(&fx.repo.join("README.md"), b"# Golden fixture\n\nIntro, conflicting.\n");
            git(&fx.repo, &["add", "-A"]);
            git_at(&fx.repo, &["commit", "--quiet", "-m", "Conflict"], Some(T0 + 240));
            git(&fx.repo, &["checkout", "--quiet", "main"]);
        }),
        case("git.checkMergeConflicts", "no_such_target", Clean, |_| {
            json!({ "workspaceId": WS, "targetBranch": "feature/missing" })
        }),
        // ---- git.changes --------------------------------------------------
        case("git.changes", "dirty", Dirty, ws),
        case("git.changes", "clean", Clean, ws),
        case("git.changes", "unknown_git_root", Dirty, |_| {
            json!({ "workspaceId": WS, "gitRootId": "root-missing" })
        }),
        // ---- git.diffs ----------------------------------------------------
        case("git.diffs", "worktree", Dirty, ws),
        case("git.diffs", "staged", Dirty, |_| {
            json!({ "workspaceId": WS, "staged": true })
        }),
        case("git.diffs", "path", Dirty, |_| {
            json!({ "workspaceId": WS, "path": "README.md" })
        }),
        case("git.diffs", "paths_binary_and_mode", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["assets/logo.bin", "run.sh"] })
        }),
        case("git.diffs", "commit", Clean, |fx| {
            json!({ "workspaceId": WS, "commitHash": fx.sha("c2") })
        }),
        case("git.diffs", "root_commit", Clean, |fx| {
            json!({ "workspaceId": WS, "commitHash": fx.sha("c1") })
        }),
        case("git.diffs", "small_budget", Dirty, |_| {
            json!({ "workspaceId": WS, "maxBytes": 200 })
        }),
        case("git.diffs", "clean", Clean, ws),
        case("git.diffs", "bad_paths", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": "README.md" })
        }),
        case("git.diffs", "unknown_commit", Clean, |_| {
            json!({ "workspaceId": WS, "commitHash": "0123456789012345678901234567890123456789" })
        }),
        // ---- git.commitDetails -------------------------------------------
        case("git.commitDetails", "c2", Clean, |fx| {
            json!({ "workspaceId": WS, "commitHash": fx.sha("c2") })
        }),
        case("git.commitDetails", "root", Clean, |fx| {
            json!({ "workspaceId": WS, "commitHash": fx.sha("c1") })
        }),
        case("git.commitDetails", "unknown", Clean, |_| {
            json!({ "workspaceId": WS, "commitHash": "0123456789012345678901234567890123456789" })
        }),
        case("git.commitDetails", "missing_hash", Clean, ws),
        // ---- git.commits --------------------------------------------------
        case("git.commits", "default", Clean, ws),
        case("git.commits", "limit_one", Clean, |_| {
            json!({ "workspaceId": WS, "limit": 1 })
        }),
        case("git.commits", "page_param", Clean, |_| {
            json!({ "workspaceId": WS, "page": { "limit": 2 } })
        }),
        case("git.commits", "unknown_workspace", Clean, unknown_ws),
        // ---- git.showFile / git.showFileChunk ----------------------------
        case("git.showFile", "head", Dirty, |_| {
            json!({ "workspaceId": WS, "filePath": "README.md", "ref": "HEAD" })
        }),
        case("git.showFile", "old_commit", Clean, |fx| {
            json!({ "workspaceId": WS, "filePath": "README.md", "ref": fx.sha("c1") })
        }),
        case("git.showFile", "binary", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "assets/logo.bin", "ref": "HEAD" })
        }),
        case("git.showFile", "truncated", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "src/lib.rs", "ref": "HEAD", "maxBytes": 8 })
        }),
        case("git.showFile", "missing_file", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "nope.txt", "ref": "HEAD" })
        }),
        case("git.showFile", "bad_ref", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "README.md", "ref": "no-such-ref" })
        }),
        case("git.showFile", "missing_ref", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "README.md" })
        }),
        case("git.showFileChunk", "text", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "src/lib.rs", "ref": "HEAD", "offset": 4, "length": 10 })
        }),
        case("git.showFileChunk", "binary", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "assets/logo.bin", "ref": "HEAD", "offset": 0, "length": 64 })
        }),
        case("git.showFileChunk", "past_end", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "README.md", "ref": "HEAD", "offset": 4096, "length": 10 })
        }),
        case("git.showFileChunk", "missing_length", Clean, |_| {
            json!({ "workspaceId": WS, "filePath": "README.md", "ref": "HEAD", "offset": 0 })
        }),
        // ---- git.numstat --------------------------------------------------
        case("git.numstat", "worktree", Dirty, ws),
        case("git.numstat", "staged", Dirty, |_| {
            json!({ "workspaceId": WS, "staged": true })
        }),
        case("git.numstat", "base_ref", Clean, |_| {
            json!({ "workspaceId": WS, "baseRef": "origin/main" })
        }),
        case("git.numstat", "base_sha_paths", Clean, |fx| {
            json!({ "workspaceId": WS, "baseCommitSha": fx.sha("c1"), "paths": ["src/lib.rs"] })
        }),
        case("git.numstat", "bad_base", Clean, |_| {
            json!({ "workspaceId": WS, "baseRef": "no-such-ref" })
        }),
        // ---- git.branchDiff -----------------------------------------------
        case("git.branchDiff", "base_ref", Clean, |_| {
            json!({ "workspaceId": WS, "baseRef": "origin/main" })
        }),
        case("git.branchDiff", "base_sha", Clean, |fx| {
            json!({ "workspaceId": WS, "baseCommitSha": fx.sha("c1") })
        }),
        case("git.branchDiff", "target_side", Clean, |_| {
            json!({ "workspaceId": WS, "baseRef": "main", "targetRef": "feature/side" })
        }),
        case("git.branchDiff", "missing_base", Clean, ws),
        case("git.branchDiff", "bad_base", Clean, |_| {
            json!({ "workspaceId": WS, "baseRef": "no-such-ref" })
        }),
        // ---- git.getRemoteUrl ---------------------------------------------
        case("git.getRemoteUrl", "origin", Clean, |fx| {
            json!({ "repoPath": fx.repo_s() })
        }),
        case("git.getRemoteUrl", "no_such_remote", Clean, |fx| {
            json!({ "repoPath": fx.repo_s(), "remoteName": "upstream" })
        }),
        case("git.getRemoteUrl", "not_a_repo", Clean, |fx| {
            json!({ "repoPath": fx.plain.display().to_string() })
        }),
        case("git.getRemoteUrl", "missing_path", Clean, |fx| {
            json!({ "repoPath": fx.root.join("nope").display().to_string(), "workspaceId": WS })
        }),
        // ---- retired --------------------------------------------------------
        case("git.commit", "retired", Dirty, |_| {
            json!({ "workspaceId": WS, "message": "m" })
        }),
        case("git.diff", "retired", Dirty, ws),
        case("git.log", "retired", Dirty, ws),
        case("file-tracking.getLineStats", "retired", Dirty, ws),
        // ---- file-tracking.* ----------------------------------------------
        case("file-tracking.getChanges", "dirty", Dirty, ws),
        case("file-tracking.getChanges", "filter", Dirty, |_| {
            json!({ "workspaceId": WS, "filter": { "stage": "staged", "filePattern": "*.txt" } })
        }),
        case("file-tracking.getChanges", "unknown_workspace", Dirty, unknown_ws),
        case("file-tracking.loadCommits", "default", Clean, ws),
        case("file-tracking.loadCommits", "limit_one", Clean, |_| {
            json!({ "workspaceId": WS, "limit": 1 })
        }),
        case("file-tracking.loadCommits", "include_older", Clean, |_| {
            json!({ "workspaceId": WS, "includeOlder": true })
        }),
        case("file-tracking.loadCommits", "unknown_workspace", Clean, unknown_ws),
        case("file-tracking.getAgentLocks", "dirty", Dirty, ws),
        case("file-tracking.getAgentLocks", "unknown_workspace", Dirty, unknown_ws),
        case("file-tracking.stage", "untracked", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["notes/new.txt", "README.md"] })
        })
        .after("git.status", status),
        case("file-tracking.stage", "missing_paths", Dirty, ws),
        case("file-tracking.unstage", "staged", Dirty, |_| {
            json!({ "workspaceId": WS, "paths": ["both.txt"] })
        })
        .after("git.status", status),
        case("file-tracking.unstage", "missing_paths", Dirty, ws),
        // ---- accept-changes.* ---------------------------------------------
        case("accept-changes.getStatus", "dirty", Dirty, ws),
        case("accept-changes.getStatus", "clean", Clean, ws),
        case("accept-changes.getStatus", "unknown_workspace", Clean, unknown_ws),
        case("accept-changes.prepare", "commit", Dirty, |_| {
            json!({ "workspaceId": WS, "action": "commit" })
        }),
        case("accept-changes.prepare", "commit_files", Dirty, |_| {
            json!({ "workspaceId": WS, "action": "commit", "files": ["README.md", "both.txt"] })
        }),
        case("accept-changes.prepare", "push", Clean, |_| {
            json!({ "workspaceId": WS, "action": "push" })
        }),
        case("accept-changes.prepare", "create_pr", Clean, |_| {
            json!({ "workspaceId": WS, "action": "create-pr" })
        }),
        case("accept-changes.prepare", "merge", Clean, |_| {
            json!({ "workspaceId": WS, "action": "merge" })
        }),
        case("accept-changes.prepare", "undo_commit", Clean, |_| {
            json!({ "workspaceId": WS, "action": "undo-commit" })
        }),
        case("accept-changes.prepare", "unknown_action", Clean, |_| {
            json!({ "workspaceId": WS, "action": "frobnicate" })
        }),
        case("accept-changes.prepare", "missing_action", Clean, ws),
        case("accept-changes.prepare", "review_saved", Dirty, |_| {
            json!({
                "workspaceId": WS,
                "action": "commit",
                "review": {
                    "root": { "workspaceId": WS, "kind": "primary" },
                    "choice": { "kind": "saved" },
                    "targetBranch": "main",
                },
            })
        }),
        case("accept-changes.prepare", "review_malformed", Dirty, |_| {
            json!({ "workspaceId": WS, "action": "commit", "review": { "root": 7 } })
        }),
        case("accept-changes.execute", "commit_local", Dirty, |_| {
            json!({
                "workspaceId": WS,
                "action": "commit",
                "commitMessage": "Accept the dirty tree",
                "options": { "stageUnstaged": true, "localOnly": true },
            })
        })
        .after("accept-changes.getStatus", accept_status_after),
        case("accept-changes.execute", "push", Clean, |_| {
            json!({ "workspaceId": WS, "action": "push" })
        })
        .after("git.status", status),
        case("accept-changes.execute", "undo_commit", Clean, |fx| {
            json!({ "workspaceId": WS, "action": "undo-commit", "upToCommitHash": fx.sha("c3") })
        })
        .after("git.status", status),
        case("accept-changes.execute", "export_rejected", Clean, |_| {
            json!({ "workspaceId": WS, "action": "export" })
        }),
        case("accept-changes.execute", "missing_action", Clean, ws),
        case("accept-changes.execute", "review_unknown_operation", Dirty, |_| {
            json!({
                "workspaceId": WS,
                "action": "commit",
                "review": {
                    "operationId": "00000000-0000-4000-8000-000000000001",
                    "root": { "workspaceId": WS, "kind": "primary" },
                },
                "commitMessage": "m",
            })
        }),
        case("accept-changes.reconcile", "unknown_operation", Dirty, |_| {
            json!({
                "workspaceId": WS,
                "operationId": "00000000-0000-4000-8000-000000000001",
                "root": { "workspaceId": WS, "kind": "primary" },
            })
        }),
        case("accept-changes.reconcile", "malformed", Dirty, ws),
        case("accept-changes.release", "unknown_operation", Dirty, |_| {
            json!({
                "workspaceId": WS,
                "operationId": "00000000-0000-4000-8000-000000000001",
                "root": { "workspaceId": WS, "kind": "primary" },
            })
        }),
        case("accept-changes.release", "malformed", Dirty, ws),
        case("accept-changes.mergePR", "no_forge", Clean, |_| {
            json!({ "workspaceId": WS, "prNumber": 1 })
        }),
        case("accept-changes.mergePR", "missing_pr_number", Clean, ws),
        case("accept-changes.addRemote", "no_remote", Clean, |_| {
            json!({ "workspaceId": WS, "remoteUrl": "https://forge.invalid/golden/repo.git" })
        })
        .prep(|fx| {
            git(&fx.repo, &["remote", "remove", "origin"]);
        })
        .after("git.getRemoteUrl", |fx| json!({ "repoPath": fx.repo_s() })),
        case("accept-changes.addRemote", "already_has_origin", Clean, |fx| {
            json!({ "workspaceId": WS, "remoteUrl": fx.origin.display().to_string() })
        }),
        case("accept-changes.addRemote", "missing_url", Clean, ws),
    ]
}

fn vcs_methods() -> BTreeSet<&'static str> {
    intent_transport::catalog::ROUTER_METHODS
        .iter()
        .copied()
        .filter(|m| NAMESPACES.iter().any(|ns| m.starts_with(ns)))
        .collect()
}

#[test]
fn every_vcs_method_has_a_case() {
    let methods = vcs_methods();
    let covered: BTreeSet<&str> = cases()
        .iter()
        .map(|c| c.method)
        .filter(|m| !RETIRED.contains(m))
        .collect();
    assert_eq!(
        methods.difference(&covered).collect::<Vec<_>>(),
        Vec::<&&str>::new(),
        "VCS methods without a golden case"
    );
    assert_eq!(
        covered.difference(&methods).collect::<Vec<_>>(),
        Vec::<&&str>::new(),
        "cases for methods the router does not dispatch (add them to RETIRED?)"
    );
    for r in RETIRED {
        assert!(!methods.contains(r), "{r} is dispatched again");
    }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn file_name(method: &str, name: &str) -> String {
    format!("{method}__{name}.json")
}

async fn run_case(tpl: &Templates, c: &Case) -> Vec<(String, String)> {
    let fx = fixture(tpl, c.tree, c.prep).await;
    let mut client = Client::connect(&fx.socket).await;
    let mut out = Vec::new();
    let raw = client.call(1, c.method, &(c.params)(&fx)).await;
    out.push((file_name(c.method, c.name), redact(&raw, &fx)));
    if let Some((method, params)) = c.after {
        let raw = client.call(2, method, &params(&fx)).await;
        out.push((
            file_name(c.method, &format!("{}__after", c.name)),
            redact(&raw, &fx),
        ));
    }
    out
}

/// What a golden reply is: `ok` or the JSON-RPC error code.
fn outcome(body: &str) -> String {
    let v: Value = serde_json::from_str(body).expect("golden is JSON");
    match v.get("error").and_then(|e| e.get("code")) {
        Some(code) => code.to_string(),
        None => "ok".to_string(),
    }
}

fn coverage_md(cases: &[Case], produced: &BTreeMap<String, String>) -> String {
    let mut by_method: BTreeMap<&str, Vec<&Case>> = BTreeMap::new();
    for c in cases {
        by_method.entry(c.method).or_default().push(c);
    }
    let mut md = String::from(
        "# VCS wire golden coverage\n\n\
         Generated by `crates/intent-app/tests/vcs_wire_goldens.rs` \
         (`UPDATE_GOLDENS=1` rewrites it); do not edit by hand.\n\n\
         Each golden is the raw JSON-RPC response line for one request, after the \
         redaction documented on `redact` in that file. `ok` cases returned a result; \
         a number is the JSON-RPC error code. `+after` marks a mutation whose \
         follow-up read is goldened too.\n\n\
         | Method | Golden | Success path | Cases |\n| --- | --- | --- | --- |\n",
    );
    for (method, cs) in &by_method {
        let retired = RETIRED.contains(method);
        let success = if retired {
            "retired (rejection pinned)".to_string()
        } else if let Some((_, why)) = ERROR_ONLY.iter().find(|(m, _)| m == method) {
            format!("error paths only: {why}")
        } else if cs
            .iter()
            .any(|c| outcome(&produced[&file_name(c.method, c.name)]) == "ok")
        {
            "yes".to_string()
        } else {
            "NO".to_string()
        };
        let list = cs
            .iter()
            .map(|c| {
                let o = outcome(&produced[&file_name(c.method, c.name)]);
                let after = if c.after.is_some() { " +after" } else { "" };
                format!("`{}` ({o}{after})", c.name)
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(md, "| `{method}` | yes | {success} | {list} |").expect("format coverage row");
    }
    let methods = vcs_methods();
    writeln!(
        md,
        "\n{} dispatched methods in the four namespaces; {} have a golden.",
        methods.len(),
        methods
            .iter()
            .filter(|m| by_method.contains_key(*m))
            .count()
    )
    .expect("format coverage totals");
    md
}

#[test]
fn vcs_wire_goldens() {
    let home = intent_services::test_support::test_tempdir("itd-vcs-home-");
    hermetic_env(home.path());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let cases = cases();
    let mut names = BTreeSet::new();
    for c in &cases {
        assert!(
            names.insert(file_name(c.method, c.name)),
            "duplicate case {}::{}",
            c.method,
            c.name
        );
    }
    let produced: BTreeMap<String, String> = rt.block_on(async {
        let template = Templates::build().await;
        let mut all = BTreeMap::new();
        for c in &cases {
            for (file, body) in run_case(&template, c).await {
                all.insert(file, body);
            }
        }
        all
    });

    let dir = golden_dir();
    let coverage = coverage_md(&cases, &produced);
    if updating() {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("clear goldens");
        }
        std::fs::create_dir_all(&dir).expect("golden dir");
        for (file, body) in &produced {
            std::fs::write(dir.join(file), format!("{body}\n")).expect("write golden");
        }
        std::fs::write(dir.join("COVERAGE.md"), &coverage).expect("write coverage");
        return;
    }

    let mut failures = Vec::new();
    for (file, body) in &produced {
        let want = std::fs::read_to_string(dir.join(file)).ok();
        let got = format!("{body}\n");
        match want {
            None => failures.push(format!("missing golden {file}\n  got: {body}")),
            Some(w) if w != got => {
                failures.push(format!(
                    "{file} differs\n  want: {}\n  got:  {body}",
                    w.trim_end()
                ));
            }
            Some(_) => {}
        }
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| {
                    Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension == "json")
                })
                .collect()
        })
        .unwrap_or_default();
    for orphan in on_disk.iter().filter(|n| !produced.contains_key(*n)) {
        failures.push(format!("orphaned golden {orphan}"));
    }
    match std::fs::read_to_string(dir.join("COVERAGE.md")) {
        Ok(c) if c == coverage => {}
        _ => failures.push("COVERAGE.md is stale".to_string()),
    }
    assert!(
        failures.is_empty(),
        "{} VCS wire golden mismatch(es); rerun with UPDATE_GOLDENS=1 only if the \
         change is intended:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
