#!/usr/bin/env python3
"""Offline packaging tests. Synthetic executable headers are not native build evidence."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('host_packaging', Path(__file__).with_name('build-atomic-host.py'))
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


class HostPackaging(unittest.TestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)
        self.temp = tempfile.TemporaryDirectory(prefix='atomic-package-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'repository'
        for relative in ('Cargo.toml', 'LICENSE', 'atomic-host/Cargo.toml', 'atomic-host/Cargo.lock',
                         'atomic-host/rust-toolchain.toml', 'atomic-host/upstream.json',
                         'crates/intent-atomic-proto/Cargo.toml', 'crates/intent-atomic-proto/src/lib.rs'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(packaging.ROOT / relative, target)
        (self.root / 'atomic-host/src').mkdir()
        (self.root / 'atomic-host/src/main.rs').write_text('fn main() {}\n')
        self.home = self.base / 'cargo-home'
        self.target_dir = self.base / 'target'
        self.output = self.base / 'payload'

    def header(self, target):
        data = bytearray(64)
        if target.endswith('apple-darwin'):
            data[:4] = b'\xcf\xfa\xed\xfe'
            struct.pack_into('<I', data, 4, 0x0100000c if target.startswith('aarch64') else 0x01000007)
        else:
            data[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<H', data, 18, 62)
        path = self.base / 'synthetic-header'
        path.write_bytes(data)
        return path

    def test_plan_keeps_host_toolchain_manifest_target_and_cargo_home_explicit(self):
        for target in packaging.SUPPORTED:
            with self.subTest(target=target):
                pin, command, environment = packaging.build_plan(self.root, target, self.home, self.target_dir)
                self.assertEqual(command[:5], ['rustup', 'run', pin['rustToolchain'], 'cargo', 'build'])
                self.assertIn(str(self.root / 'atomic-host/Cargo.toml'), command)
                self.assertIn('--locked', command)
                self.assertEqual(command[command.index('--target') + 1], target)
                self.assertEqual(environment['CARGO_HOME'], str(self.home))
                self.assertEqual(environment['CARGO_TARGET_DIR'], str(self.target_dir))

    def test_private_contract_identity_is_derived_not_fixed_to_an_old_version(self):
        proto = self.root / 'crates/intent-atomic-proto/src/lib.rs'
        old = packaging.identity(self.root)['contractVersion']
        proto.write_text(proto.read_text().replace(f'CONTRACT_VERSION: u32 = {old};', 'CONTRACT_VERSION: u32 = 987;'))
        self.assertEqual(packaging.identity(self.root)['contractVersion'], 987)

    def test_mismatched_upstream_and_cargo_pin_refuses(self):
        pin_path = self.root / 'atomic-host/upstream.json'
        pin = json.loads(pin_path.read_text())
        pin['revision'] = 'a' * 40
        pin_path.write_text(json.dumps(pin))
        with self.assertRaisesRegex(ValueError, 'exact Atomic Git pin'):
            packaging.identity(self.root)

    def test_inherited_cargo_home_configuration_refuses(self):
        self.home.mkdir()
        (self.home / 'config.toml').write_text('[patch.crates-io]\n')
        with self.assertRaisesRegex(ValueError, 'inherited configuration'):
            packaging.build_plan(self.root, packaging.SUPPORTED[0], self.home, self.target_dir)

    def test_payload_hashes_notice_and_architecture_are_exact(self):
        target = packaging.SUPPORTED[0]
        binary = self.header(target)
        manifest = packaging.stage(self.root, target, binary, 'rustc fixture (not a build)', self.output)
        self.assertEqual(manifest['binarySha256'], packaging.sha256(binary))
        self.assertEqual(manifest['sourceSha256'], packaging.source_digest(self.root))
        self.assertEqual(manifest['target'], target)
        self.assertFalse(manifest['authoritativeActivation'])
        self.assertEqual(set(path.name for path in self.output.iterdir()), packaging.OWNED_FILES)
        self.assertIn(manifest['atomicRevision'], (self.output / 'NOTICE').read_text())
        self.assertEqual((self.output / packaging.BINARY).stat().st_mode & 0o777, 0o755)
        with self.assertRaisesRegex(ValueError, 'requested thin Mach-O'):
            packaging.stage(self.root, packaging.SUPPORTED[1], binary, 'fixture', self.output)

    def test_unowned_files_and_symlink_staging_refuse(self):
        self.output.mkdir()
        (self.output / 'keep.txt').write_text('unrelated')
        with self.assertRaisesRegex(ValueError, 'unowned'):
            packaging.prepare_output(self.output)
        (self.output / 'keep.txt').unlink()
        (self.output / 'manifest.json').symlink_to(self.root / 'Cargo.toml')
        with self.assertRaisesRegex(ValueError, 'unowned'):
            packaging.prepare_output(self.output)

    def test_unsupported_target_cannot_be_presented_as_built(self):
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            packaging.build_plan(self.root, 'x86_64-pc-windows-msvc', self.home, self.target_dir)
        with patch.object(packaging, 'ROOT', self.root):
            self.assertEqual(packaging.main(['--target', 'x86_64-pc-windows-msvc', '--cargo-home', str(self.home),
                                             '--output', str(self.output), '--skip-unsupported']), 0)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_build_subprocesses_never_inherit_the_parent_repository_cargo_config(self):
        target = packaging.SUPPORTED[2]
        binary = self.header(target)
        calls = []
        def run(command, **kwargs):
            calls.append((command, kwargs))
            self.assertNotEqual(Path(kwargs['cwd']), self.root)
            self.assertNotIn(self.root, Path(kwargs['cwd']).parents)
            self.assertEqual(kwargs['env']['CARGO_HOME'], str(self.home))
            if command[3] == 'cargo':
                artifact = self.target_dir / target / 'release' / packaging.BINARY
                artifact.parent.mkdir(parents=True)
                shutil.copyfile(binary, artifact)
            return type('Result', (), {'stdout': 'rustc fixture\n'})()
        with patch.object(packaging, 'ROOT', self.root), patch.object(packaging.subprocess, 'run', side_effect=run):
            self.assertEqual(packaging.main(['--target', target, '--cargo-home', str(self.home),
                                             '--target-dir', str(self.target_dir), '--output', str(self.output)]), 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0][3:], ['rustc', '-vV'])


if __name__ == "__main__":
    unittest.main()
