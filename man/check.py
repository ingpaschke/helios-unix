#!/usr/bin/env python3
"""Format all manuals and optionally compile their C examples with the SDK."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', type=Path)
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--stage', type=Path)
    args = parser.parse_args()
    if any((args.clang, args.sdk, args.stage)) and not all((args.clang, args.sdk, args.stage)):
        parser.error('--clang, --sdk and --stage must be supplied together')
    pages = sorted(ROOT.glob('man[37]/*.[37]'))
    examples = 0
    env = dict(os.environ, LC_ALL='C', GROFF_NO_SGR='1', SOURCE_DATE_EPOCH='0')
    with tempfile.TemporaryDirectory(prefix='hu-man-') as temporary:
        for page in pages:
            run = subprocess.run(['groff', '-Tascii', '-man', '-rLL=78n', '-rLT=78n',
                                  str(page.relative_to(ROOT))],
                                 cwd=ROOT, env=env, text=True, capture_output=True)
            if run.returncode or run.stderr or len(run.stdout.strip()) < 40:
                raise RuntimeError(str(page) + '\n' + run.stderr)
            if not args.clang:
                continue
            for example in re.findall(r'^\.EX\n(.*?)^\.EE$', page.read_text(), re.M | re.S):
                source = Path(temporary) / 'example.c'
                source.write_text(example.replace('\\e', '\\'))
                command = [str(args.clang.resolve()), '--target=t800-helios', '-mcpu=t800',
                           '--sysroot=' + str(args.sdk.resolve()), '-std=gnu89',
                           '-D_BSD', '-D__HELIOS', '-D__TRAN', '-D__HELIOSTRAN',
                           '-Werror=implicit-function-declaration',
                           '-I' + str(args.stage.resolve() / 'include/helios-unix/compat'),
                           '-I' + str(ROOT.parent / 'include'),
                           '-fsyntax-only', str(source)]
                run = subprocess.run(command, text=True, capture_output=True)
                if run.returncode:
                    raise RuntimeError(str(page) + ' example\n' + run.stdout + run.stderr)
                examples += 1
    print('PASS', len(pages), 'manuals and aliases formatted without warnings;',
          examples, 'C examples checked against the SDK')


if __name__ == '__main__':
    main()
