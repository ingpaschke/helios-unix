"""Check actual hcc include ordering and rejection of native fork aliases."""
import importlib.util,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('compat_build',ROOT/'ktm-distribution/build_compat.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
inc=[b.WORK/'stage/include/helios-unix/compat',b.WORK/'stage/include/helios-unix',b.SDK/'include']
with tempfile.TemporaryDirectory(prefix='helios-sdk-') as folder:
    source=Path(folder)/'probe.c';output=Path(folder)/'probe.s'
    headers='#include <unistd.h>\n#include <sys/socket.h>\n#include <netdb.h>\n#include <stdlib.h>\n#include <glob.h>\n'
    cmd=[str(b.HCC),'-D_BSD','-D__HELIOS','-D__TRAN','-D__HELIOSTRAN','-i,'+','.join(str(p)+'/' for p in inc),'-j'+','.join(str(p)+'/' for p in inc),str(source),'-s'+str(output)]
    source.write_text(headers+'int main(void){struct addrinfo *p=0;glob_t g;socklen_t n=0;freeaddrinfo(p);return n;}\n')
    p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode==0,p.stdout+p.stderr
    source.write_text(headers+'int main(void){return fork();}\n')
    p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode!=0 and 'negative' in p.stderr,p.stdout+p.stderr
print('PASS opt-in SDK types, header order and fork rejection')
