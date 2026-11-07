#!/usr/bin/env python3
"""Check fixed control records without requiring a network or cryptography."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='hu-offload-contract-') as directory:
    binary = Path(directory) / 'contract'
    sources = ['ssh.c', 'ssh_offload.c', 'tls.c', 'tls_offload.c', 'tls_socket.c']
    subprocess.run([
        os.environ.get('CC', 'cc'), '-std=c99', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-g', '-I' + str(root / 'include'),
        str(Path(__file__).with_name('offload_contract.c')),
        *[str(root / 'src' / name) for name in sources], '-o', str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
