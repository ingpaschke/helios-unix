#!/usr/bin/env python3
"""Check SSH encoding negotiation, input preservation and cleanup over PTYs."""
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='ssh-terminal-') as name:
    binary = Path(name)/'check'
    subprocess.run([os.environ.get('CC', 'cc'), '-D_DEFAULT_SOURCE', '-std=c99',
                    '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                    '-I'+str(root/'include'), str(Path(__file__).with_name('ssh_terminal.c')),
                    '-o', str(binary)], check=True)

    def check(reply, expected, keys='', term='xterm-256color', redirected=False):
        master, slave = pty.openpty()
        process = subprocess.Popen([str(binary)], stdin=slave,
            stdout=subprocess.PIPE if redirected else slave, stderr=subprocess.PIPE,
            env={**os.environ, 'TERM': term})
        os.close(slave)
        output = b''
        sent = False
        deadline = time.monotonic()+5
        try:
            while time.monotonic()<deadline:
                ready, _, _ = select.select([master], [], [], .05)
                if ready:
                    try:
                        data = os.read(master, 4096)
                    except OSError:
                        break
                    output += data
                    if not sent and b'\x1b[?1020$p' in output:
                        sent = True
                        if reply:
                            # Fragment the report and interleave real keyboard input.
                            os.write(master, reply[:5])
                            time.sleep(.02)
                            os.write(master, reply[5:])
                if process.poll() is not None:
                    break
            stdout, stderr = process.communicate(timeout=2)
            assert process.returncode == 0, stderr
            assert stderr.decode().strip() == f'mode={expected} keys={keys}', stderr
            if expected >= 0:
                restore = b'\x1b%G' if expected else b'\x1b%@'
                assert output == b'\x1b[?1020$p\x1b%G'+restore, output
            else:
                assert output == (b'\x1b[?1020$p' if sent else b''), output
            if redirected:
                assert stdout == b'', stdout
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
            os.close(master)

    check(b'abc\x1b[?1020;2$yZ', 0, '6162635a')
    check(b'\x1b[?1020;1$y', 1)
    check(b'\x1b[?1020;3$y', 1)
    check(b'\x1b[?1020;4$y', 0)
    check(b'\x1b[?1020;0$y', -1)
    check(b'abc', -1, '616263')
    check(None, -1, term='vt100')
    check(None, -1, redirected=True)
print('PASS SSH encoding: Latin-1/UTF-8 restore, fragmented replies, typeahead, unsupported terminals and redirection')
