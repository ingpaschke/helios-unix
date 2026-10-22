#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='hu-glob-') as temporary:
    directory=Path(temporary);binary=directory/'test';files=directory/'files';files.mkdir()
    subprocess.run(['cc','-std=c99','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-g','-pthread','-I'+str(root/'include'),str(Path(__file__).with_name('glob_bounds.c')),str(root/'src/glob.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary),str(files)],check=True,timeout=10)
