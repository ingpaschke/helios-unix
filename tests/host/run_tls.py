#!/usr/bin/env python3
"""Host provider contract test; mock engine deliberately performs no TLS crypto."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='hu-tls-contract-') as d:
    binary=Path(d)/'contract'
    subprocess.run([os.environ.get('CC','cc'),'-std=c99','-Wall','-Wextra',
        '-Wno-misleading-indentation','-Werror','-fsanitize=address,undefined','-g','-Wl,--wrap=malloc','-Wl,--wrap=calloc',
        '-I'+str(root/'include'),str(Path(__file__).with_name('tls_contract.c')),
        *[str(root/'src'/n) for n in ['tls.c','tls_fd.c','tls_offload.c']],'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=10)
