#!/usr/bin/env python3
"""Check provider ownership and a native engine over a plain byte transport."""
from pathlib import Path
import os
import subprocess
import tempfile
root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='hu-ssh-contract-') as name:
    binary = Path(name)/'contract'
    subprocess.run([os.environ.get('CC','cc'), '-std=c99', '-Wall', '-Wextra',
        '-Werror',  '-fsanitize=address,undefined',
        '-g', '-I'+str(root/'include'), str(root/'src/ssh.c'),
        str(Path(__file__).with_name('ssh_contract.c')), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print('PASS SSH provider ownership, native byte transport and input validation')
