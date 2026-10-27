#!/usr/bin/env python3
"""Build helios-unix against an SP2 SDK for a selected Transputer CPU."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
CPUS = {'generic': '-t4', 't425': '-t5', 't800': '-t8'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class UnixBuild:
    def __init__(self, work, sdk, assembler, helios_ng, toolchain='/opt/llvm-t800',
                 cpu='t800', tests=False):
        if cpu not in CPUS:
            raise ValueError('Unsupported CPU: ' + cpu)
        self.work, self.sdk, self.asm, self.helios_ng, self.toolchain = [
            Path(p).resolve() for p in (work, sdk, assembler, helios_ng, toolchain)]
        self.cpu, self.tests = cpu, tests
        self.hcc = self.toolchain / 'bin/hcc'
        self.runtime = self.toolchain / 'sysroots/helios/lib/llvmrt-generic.lib'
        self.stage = self.work / 'stage'

    def input_id(self):
        files = [Path(__file__), self.helios_ng / 'posix/dns-resolver.h',
                 self.hcc, self.asm, self.runtime]
        files += [p for directory in ['src', 'include', 'services', 'docs']
                  for p in (ROOT / directory).rglob('*') if p.is_file()]
        files += [ROOT / 'capabilities.json', ROOT / 'LICENSE']
        if self.tests:
            files += list((ROOT / 'tests').glob('*.c'))
        files += [p for p in (self.sdk / 'include').rglob('*') if p.is_file()]
        files += [self.sdk / 'lib' / n for n in
                  ['c0.o', 'c.lib', 'bsd.lib', 'helios.lib', 'posix.def', 'Posix', 'Clib']]
        value = hashlib.sha256(json.dumps({'cpu': self.cpu, 'tests': self.tests}).encode())
        for p in sorted(set(files)):
            value.update(str(p).encode()); value.update(p.read_bytes())
        return value.hexdigest()

    def validate(self):
        info = json.loads((self.work / 'build-info.json').read_text())
        if info['input_id'] != self.input_id():
            raise RuntimeError('Rebuild helios-unix: inputs or CPU changed')
        actual = {str(p.relative_to(self.stage)): digest(p)
                  for p in self.stage.rglob('*') if p.is_file()}
        if actual != info['files']:
            raise RuntimeError('Modified helios-unix installation stage')
        return info

    def run(self, args, name):
        logs = self.work / 'logs'; logs.mkdir(parents=True, exist_ok=True)
        with (logs / (name + '.log')).open('w') as output:
            output.write(json.dumps(list(map(str, args))) + '\n'); output.flush()
            subprocess.run(list(map(str, args)), stdout=output,
                           stderr=subprocess.STDOUT, check=True)

    def compile(self, source, name):
        inc = [ROOT / 'include', self.helios_ng / 'posix', self.sdk / 'include']
        out = self.work / 'obj' / name
        self.run([self.hcc, CPUS[self.cpu], '-D_BSD', '-D__HELIOS', '-D__TRAN', '-D__HELIOSTRAN',
                  '-i,' + ','.join(str(p) + '/' for p in [source.parent, *inc]),
                  '-j' + ','.join(str(p) + '/' for p in inc), source,
                  '-s' + str(out.with_suffix('.s'))], name + '-compile')
        self.run([self.asm, '-p', '-o', out.with_suffix('.o'), out.with_suffix('.s')], name + '-asm')
        return out.with_suffix('.o')

    def build(self):
        try:
            return self.validate()
        except (OSError, ValueError, KeyError, RuntimeError):
            pass
        inputs = self.input_id()
        (self.work / 'build-info.json').unlink(missing_ok=True)
        for folder in [self.stage, self.work / 'bin']:
            if folder.exists(): shutil.rmtree(folder)
        for name in ['obj', 'bin', 'stage/bin', 'stage/lib', 'stage/include/helios-unix']:
            (self.work / name).mkdir(parents=True, exist_ok=True)
        objects = [self.compile(p, p.stem) for p in sorted((ROOT / 'src').glob('*.c'))]
        archive = self.stage / 'lib/helios-unix.lib'
        self.run([self.asm, '-p', '-o', archive, *objects, self.sdk / 'lib/posix.def'], 'archive')
        headers = self.stage / 'include/helios-unix'
        shutil.copytree(ROOT / 'include', headers, dirs_exist_ok=True)
        overlay = headers / 'compat'
        for name in ['unistd.h', 'stdlib.h', 'netdb.h', 'sys/socket.h']:
            destination = overlay / 'native' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.sdk / 'include' / name, destination)
            path = overlay / name; path.parent.mkdir(parents=True, exist_ok=True)
            guard = 'HU_OVERLAY_' + name.upper().replace('/', '_').replace('.', '_')
            text = '#ifndef ' + guard + '\n#define ' + guard + '\n#include "native/' + name + '"\n'
            if name == 'unistd.h':
                text += ('\n#undef fork\n#define fork(...) ((int)sizeof(char[-1])) /* use spawn; native fork is vfork */\n'
                         '#ifndef HU_ENABLE_NATIVE_VFORK\n#define vfork(...) ((int)sizeof(char[-1]))\n#endif\n')
            elif name == 'stdlib.h': text += 'int mkstemp(char *);\n'
            elif name == 'netdb.h': text += '#include <helios/unix/netdb.h>\n'
            elif name == 'sys/socket.h': text += '#ifndef HU_SOCKLEN_T\n#define HU_SOCKLEN_T\ntypedef unsigned int socklen_t;\n#endif\n'
            path.write_text(text + '#endif\n')
        (overlay / 'glob.h').write_text('#include <helios/unix/glob.h>\n')
        (self.stage / 'lib/helios-unix-flags.json').write_text(json.dumps({
            'cpu': self.cpu, 'include_order': ['/helios/include/helios-unix/compat',
                '/helios/include/helios-unix', '/helios/include'],
            'archive': '/helios/lib/helios-unix.lib',
            'definitions': ['_BSD', '__HELIOS', '__TRAN', '__HELIOSTRAN'],
            'fork': False, 'poll': 'hu_poll', 'threads': 'application-thread API profile'
        }, indent=2) + '\n')
        programs = list((ROOT / 'services').glob('*.c'))
        if self.tests: programs += list((ROOT / 'tests').glob('*.c'))
        for source in sorted(programs):
            obj = self.compile(source, 'program-' + source.stem)
            self.run([self.asm, '-o', self.work / 'bin' / source.stem,
                      '-n' + source.stem, '-s65536', '-h131072', self.sdk / 'lib/c0.o', obj,
                      '-l' + str(archive), *['-l' + str(self.sdk / 'lib' / n)
                      for n in ['bsd.lib', 'c.lib', 'helios.lib']], '-l' + str(self.runtime)], source.stem + '-link')
        shutil.copyfile(self.work / 'bin/hu-resolve', self.stage / 'lib/hu-resolve')
        shutil.copyfile(self.work / 'bin/hu-ssh', self.stage / 'bin/ssh')
        shutil.copyfile(ROOT / 'capabilities.json', self.stage / 'lib/helios-unix-capabilities.json')
        shutil.copytree(ROOT / 'docs', self.stage / 'local/share/helios-unix')
        shutil.copyfile(ROOT / 'LICENSE', self.stage / 'local/share/helios-unix/COPYING')
        if self.input_id() != inputs: raise RuntimeError('helios-unix inputs changed during build')
        info = {'abi': 1, 'version': '0.1-dev', 'cpu': self.cpu, 'input_id': inputs,
                'files': {str(p.relative_to(self.stage)): digest(p)
                          for p in self.stage.rglob('*') if p.is_file()}}
        (self.work / 'build-info.json').write_text(json.dumps(info, indent=2) + '\n')
        return self.validate()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['build', 'verify'], nargs='?', default='build')
    ap.add_argument('--work', type=Path, default=ROOT / 'work')
    ap.add_argument('--sdk', type=Path, required=True)
    ap.add_argument('--asm', type=Path, required=True)
    ap.add_argument('--helios-ng', type=Path, required=True)
    ap.add_argument('--toolchain', type=Path, default=Path('/opt/llvm-t800'))
    ap.add_argument('--cpu', choices=list(CPUS), default='t800')
    ap.add_argument('--tests', action='store_true', help='also build native regression programs')
    args = ap.parse_args()
    build = UnixBuild(args.work, args.sdk, args.asm, args.helios_ng, args.toolchain, args.cpu, args.tests)
    if args.command == 'verify': build.validate()
    else: build.build()
    print(build.stage)


if __name__ == '__main__':
    main()
