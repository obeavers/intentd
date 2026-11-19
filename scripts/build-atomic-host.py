#!/usr/bin/env python3
"""Build the experimental isolated host and stage its exact per-target payload.

This command never builds through intentd's Cargo workspace/configuration. CI
provisions the pinned toolchain and target first. --plan performs no Cargo call.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
BINARY = 'intent-atomic-host'
OWNED_FILES = {BINARY, 'manifest.json', 'LICENSE', 'NOTICE', 'upstream.json'}
SUPPORTED = ('aarch64-apple-darwin', 'x86_64-apple-darwin',
             'x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(root):
    host = root / 'atomic-host'
    pin = json.loads((host / 'upstream.json').read_text())
    package = tomllib.loads((host / 'Cargo.toml').read_text())
    toolchain = tomllib.loads((host / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    revision = pin['revision']
    if not re.fullmatch(r'[a-f0-9]{40}', revision) or pin['toolchain'] != toolchain:
        raise ValueError('Atomic revision/toolchain pin mismatch')
    if tuple(pin['release_targets']) != SUPPORTED:
        raise ValueError('Atomic release target inventory drifted')
    if 'workspace' not in package or 'atomic-host' not in tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['exclude']:
        raise ValueError('Atomic host must remain an excluded independent Cargo workspace')
    for name in ('atomic-core', 'atomic-agent', 'atomic-repository', 'libatomic', 'atomic-semantic'):
        dependency = package['dependencies'][name]
        if dependency.get('git') != pin['repository'] or dependency.get('rev') != revision:
            raise ValueError(f'{name} must use the exact Atomic Git pin')
    lock = tomllib.loads((host / 'Cargo.lock').read_text())
    sources = [p['source'] for p in lock['package'] if p.get('source', '').startswith('git+' + pin['repository'])]
    expected = f"git+{pin['repository']}?rev={revision}#{revision}"
    if not sources or any(source != expected for source in sources):
        raise ValueError('Atomic Cargo.lock Git source mismatch')
    proto = (root / 'crates/intent-atomic-proto/src/lib.rs').read_text()
    def constant(name):
        match = re.search(rf'pub const {name}: [^=]+ = ([^;]+);', proto)
        if not match:
            raise ValueError(f'missing private host identity {name}')
        return json.loads(match[1])
    if constant('ATOMIC_REVISION') != revision:
        raise ValueError('daemon/host Atomic revision mismatch')
    return {'schemaVersion': 1, 'binary': BINARY, 'packageVersion': package['package']['version'],
            'atomicRevision': revision, 'rustToolchain': toolchain,
            'contractVersion': constant('CONTRACT_VERSION'), 'storeFormat': constant('STORE_FORMAT'),
            'hostLockSha256': sha256(host / 'Cargo.lock'), 'authoritativeActivation': False}


def source_digest(root):
    files = [root / 'atomic-host' / name for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'upstream.json')]
    files += sorted((root / 'atomic-host/src').rglob('*.rs'))
    files += [root / 'crates/intent-atomic-proto/Cargo.toml']
    files += sorted((root / 'crates/intent-atomic-proto/src').rglob('*.rs'))
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(root)).encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def build_plan(root, target, cargo_home, target_dir, qualification_target=None):
    pinned = identity(root)
    if qualification_target is not None and (qualification_target != target or
                                             qualification_target != 'aarch64-unknown-linux-gnu'):
        raise ValueError('qualification target must explicitly select native Linux aarch64 GNU')
    if target not in SUPPORTED and qualification_target != target:
        raise ValueError('Atomic host target is unavailable')
    if qualification_target is not None:
        pinned.update(qualificationOnly=True, qualificationTarget=qualification_target)
    for name in ('config', 'config.toml'):
        if (cargo_home / name).exists():
            raise ValueError('Atomic host requires a Cargo home without inherited configuration')
    command = ['rustup', 'run', pinned['rustToolchain'], 'cargo', 'build', '--manifest-path',
               str((root / 'atomic-host/Cargo.toml').resolve()), '--locked', '--release',
               '--target', target, '--bin', BINARY, '--features', 'git2/vendored-openssl']
    return pinned, command, {'CARGO_HOME': str(cargo_home.resolve()),
                            'CARGO_TARGET_DIR': str(target_dir.resolve()),
                            'RUSTUP_TOOLCHAIN': pinned['rustToolchain']}


def verify_architecture(binary, target):
    data = binary.read_bytes()[:64]
    if target.endswith('apple-darwin'):
        cpu = 0x0100000c if target.startswith('aarch64') else 0x01000007
        if len(data) < 8 or data[:4] != b'\xcf\xfa\xed\xfe' or struct.unpack_from('<I', data, 4)[0] != cpu:
            raise ValueError('Atomic host is not the requested thin Mach-O architecture')
    else:
        machines = {'x86_64-unknown-linux-gnu': 62, 'x86_64-unknown-linux-musl': 62,
                    'aarch64-unknown-linux-gnu': 183}
        machine = machines.get(target)
        if machine is None or len(data) < 20 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != machine:
            raise ValueError('Atomic host is not the requested native ELF architecture')


def prepare_output(output):
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or any(path.name not in OWNED_FILES or path.is_symlink() or not path.is_file() for path in output.iterdir()):
        raise ValueError('Atomic staging directory contains unowned entries')


def stage(root, target, binary, rustc_version, output):
    pinned = identity(root)
    if target not in SUPPORTED:
        raise ValueError('qualification-only targets cannot be staged as release payloads')
    verify_architecture(binary, target)
    prepare_output(output)
    shutil.copyfile(binary, output / BINARY)
    (output / BINARY).chmod(0o755)
    shutil.copyfile(root / 'LICENSE', output / 'LICENSE')
    shutil.copyfile(root / 'atomic-host/upstream.json', output / 'upstream.json')
    (output / 'NOTICE').write_text('Experimental Intent Atomic host\n\n'
        'Includes Atomic (https://github.com/atomicdotdev/atomic), licensed under Apache-2.0,\n'
        f"at revision {pinned['atomicRevision']}. See LICENSE and upstream.json.\n"
        'Bundling does not activate native workspace authority or advertise a capability.\n')
    pinned.update({'target': target, 'rustcVersion': rustc_version.strip(),
                   'sourceSha256': source_digest(root), 'binarySha256': sha256(output / BINARY)})
    (output / 'manifest.json').write_text(json.dumps(pinned, indent=2, sort_keys=True) + '\n')
    return pinned


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--cargo-home', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, default=ROOT / 'atomic-host/target')
    parser.add_argument('--output', type=Path, default=ROOT / 'packaging/libexec/atomic-host')
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--skip-unsupported', action='store_true')
    args = parser.parse_args(argv)
    if args.target in ('x86_64-pc-windows-msvc', 'aarch64-unknown-linux-musl') and args.skip_unsupported:
        prepare_output(args.output)
        for path in args.output.iterdir():
            path.unlink()
        print(f'Atomic host unavailable for {args.target}; no binary staged')
        return 0
    pinned, command, environment = build_plan(ROOT, args.target, args.cargo_home, args.target_dir)
    if args.plan:
        print(json.dumps({'target': args.target, 'identity': pinned, 'command': command,
                          'environment': environment, 'cwd': 'fresh temporary directory outside both workspaces',
                          'qualification': 'not-run'}, indent=2))
        return 0
    args.cargo_home.mkdir(parents=True, exist_ok=True)
    child_env = dict(os.environ)
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC', 'RUSTDOC', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTDOC'):
        child_env.pop(name, None)
    child_env.update(environment)
    before = source_digest(ROOT)
    # Cargo discovers config from cwd, not --manifest-path. Never enter atomic-host:
    # doing so would inherit intentd/.cargo/config.toml's independent tokio patches.
    with tempfile.TemporaryDirectory(prefix='intent-atomic-build-') as cwd:
        rustc = subprocess.run(['rustup', 'run', pinned['rustToolchain'], 'rustc', '-vV'],
                               cwd=cwd, env=child_env, check=True, capture_output=True, text=True).stdout
        subprocess.run(command, cwd=cwd, env=child_env, check=True)
    if source_digest(ROOT) != before:
        raise ValueError('Atomic host sources changed during the build')
    artifact = args.target_dir / args.target / 'release' / BINARY
    manifest = stage(ROOT, args.target, artifact, rustc, args.output)
    print(f"Staged {manifest['binary']} for {args.target}; sha256={manifest['binarySha256']}")
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Atomic host packaging failed: {error}')
