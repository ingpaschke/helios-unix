#!/usr/bin/env python3
"""The standalone build cache must follow the actual compiler and settings."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('unix_build', ROOT / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildCache(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='helios-unix-build-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        toolchain = self.root / 'install/tools/toolchain'
        sdk = self.root / 'sdk'
        hng = self.root / 'hng'
        files = [toolchain / 'bin/hcc', toolchain / 'bin/clang',
                 toolchain / 'sysroots/helios/lib/llvmrt-generic.lib',
                 self.root / 'asm', hng / 'posix/dns-resolver.h',
                 sdk / 'include/stdio.h']
        files += [sdk / 'lib' / name for name in
                  ['c0.o', 'c.lib', 'bsd.lib', 'helios.lib', 'posix.def', 'Posix', 'Clib']]
        for path in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture\n')
            path.chmod(0o755)
        self.compiler = toolchain / 'bin/clang'
        self.build = builder.UnixBuild(self.root / 'work', sdk, self.root / 'asm',
                                       hng, toolchain)

    def record_stage(self):
        self.build.stage.mkdir(parents=True)
        (self.build.work / 'build-info.json').write_text(json.dumps({
            'input_id': self.build.input_id(), 'files': {}}))
        self.build.validate()

    @patch.dict(os.environ, {}, clear=True)
    def test_compiler_replacement_rejects_cached_stage(self):
        self.record_stage()
        self.compiler.write_text('replacement compiler\n')
        with self.assertRaisesRegex(RuntimeError, 'Rebuild'):
            self.build.validate()

    @patch.dict(os.environ, {}, clear=True)
    def test_effective_compiler_environment(self):
        original = self.build.input_id()
        for key, value in [('HCC_OPT', '2'), ('HCC_CLANG_FLAGS', '-g'),
                           ('HCC_WARNINGS', 'all'), ('HCC_SYSROOT', '/different/sdk')]:
            with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                self.assertNotEqual(self.build.input_id(), original)
        with patch.dict(os.environ, {'UNRELATED_SETTING': 'ignored'}):
            self.assertEqual(self.build.input_id(), original)

    @patch.dict(os.environ, {}, clear=True)
    def test_configured_compiler_and_path_lookup(self):
        selected = self.root / 'other-clang'
        selected.write_text('other compiler\n')
        selected.chmod(0o755)
        original = self.build.input_id()
        with patch.dict(os.environ, {'HCC_CLANG': 'other-clang', 'PATH': str(self.root)}):
            self.assertEqual(self.build.compiler(), selected)
            self.assertNotEqual(self.build.input_id(), original)
            before = self.build.input_id()
            selected.write_text('other compiler updated\n')
            self.assertNotEqual(self.build.input_id(), before)

    @patch.dict(os.environ, {}, clear=True)
    def test_fallback_compiler_selection(self):
        self.compiler.unlink()
        with self.assertRaisesRegex(RuntimeError, 'Clang not found'):
            self.build.compiler()
        selected = self.root / 'clang'
        selected.write_text('PATH compiler\n')
        selected.chmod(0o755)
        with patch.dict(os.environ, {'PATH': str(self.root)}):
            self.assertEqual(self.build.compiler(), selected)

    @patch.dict(os.environ, {'HCC_DRYRUN': '1'}, clear=True)
    def test_dry_run_cannot_publish_an_old_object(self):
        with self.assertRaisesRegex(RuntimeError, 'HCC_DRYRUN'):
            self.build.build()


if __name__ == '__main__':
    unittest.main()
