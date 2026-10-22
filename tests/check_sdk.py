"""Check actual hcc include ordering and rejection of native fork aliases."""
import argparse,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--stage',type=Path,default=ROOT/'ktm-distribution/work/compat/stage')
ap.add_argument('--sdk',type=Path,default=ROOT/'ktm-distribution/work/sp1/prod/TRAN')
ap.add_argument('--hcc',type=Path,default=Path('/opt/llvm-t800/bin/hcc'))
args=ap.parse_args()
inc=[args.stage/'include/helios-unix/compat',args.stage/'include/helios-unix',args.sdk/'include']
with tempfile.TemporaryDirectory(prefix='helios-sdk-') as folder:
    source=Path(folder)/'probe.c';output=Path(folder)/'probe.s'
    headers='#include <unistd.h>\n#include <sys/socket.h>\n#include <netdb.h>\n#include <stdlib.h>\n#include <glob.h>\n'
    cmd=[str(args.hcc),'-D_BSD','-D__HELIOS','-D__TRAN','-D__HELIOSTRAN','-i,'+','.join(str(p)+'/' for p in inc),'-j'+','.join(str(p)+'/' for p in inc),str(source),'-s'+str(output)]
    source.write_text(headers+'int main(void){struct addrinfo *p=0;glob_t g;socklen_t n=0;freeaddrinfo(p);return n;}\n')
    p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode==0,p.stdout+p.stderr
    source.write_text(headers+'int main(void){return fork();}\n')
    p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode!=0 and 'negative' in p.stderr,p.stdout+p.stderr
print('PASS opt-in SDK types, header order and fork rejection')
