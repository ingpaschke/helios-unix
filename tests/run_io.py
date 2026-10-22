"""Native socket probe in a disposable emulator root.

Build the SDK/core and compatibility probes first. Build ioserver-linux with
IOS_TARGET=native, or set HELIOS_RUN_IOSERVER to a current native io-server.
HELIOS_TEST_BASE optionally supplies the vintage root used for boot utilities.
The /internet readiness ioctl is required; this is a Linux io-server test.
"""
from pathlib import Path
import os,re,socket,subprocess,threading,shutil,time,tempfile
ROOT=Path(__file__).resolve().parents[2]

def main():
    sdk=ROOT/'ktm-distribution/work/sp1/prod/TRAN'
    probe=ROOT/'ktm-distribution/work/compat/bin/io'
    base=Path(os.environ.get('HELIOS_TEST_BASE',str(ROOT/'t4-root')))
    if not probe.is_file() or not (sdk/'lib/Posix').is_file():
        raise RuntimeError('Build the current core and compatibility probes first')
    with tempfile.TemporaryDirectory(prefix='helios-io-probe-') as temporary:
        work=Path(temporary);root=work/'helios'
        shutil.copytree(base,root,symlinks=True)
        shutil.copytree(sdk/'lib',root/'lib',dirs_exist_ok=True)
        shutil.copy2(probe,root/'bin/compat-io')
        (root/'etc/initrc').write_text('ifabsent /window run -e /helios/lib/window window\n'
            'ifabsent /fifo run -e /helios/lib/fifo fifo\nwaitfor /fifo\n'
            'console /window console\nrun -e /helios/bin/login login\n')
        config=(ROOT/'ioserver-linux/host.con').read_text()
        for key,value in {'helios_directory':root,'system_image':root/'lib/nucleus',
                          'bootfile':root/'lib/nboot.i','transputer_memory':'0x1000000'}.items():
            config=re.sub(r'^'+key+r'\s*=.*$',key+' = '+str(value),config,flags=re.M)
        con=work/'host.con';con.write_text(config+'\ninternet\n')
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(2);listener.settimeout(45)
        errors=[]
        def serve():
            try:
                connection,_=listener.accept()
                with connection:
                    connection.settimeout(20);data=b''
                    while True:
                        chunk=connection.recv(64)
                        if not chunk:break
                        data+=chunk
                    if data!=b'request':raise RuntimeError('Unexpected request: '+repr(data))
                    connection.sendall(b'reply')
                connection,_=listener.accept()
                with connection:
                    time.sleep(.2);connection.shutdown(socket.SHUT_WR);time.sleep(.2)
            except Exception as error:errors.append(repr(error))
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        try:
            env=dict(os.environ,HELIOS_RUN_CON=str(con),HELIOS_RUN_T4ARGS='-sm 24')
            result=subprocess.run([str(ROOT/'ioserver-linux/helios-run'),'-s8','-t30','-T90','-q',
                '/helios/bin/compat-io 127.0.0.1 '+str(listener.getsockname()[1])],
                env=env,capture_output=True,text=True,timeout=100)
            print(result.stdout);print(result.stderr)
            thread.join(2)
            if result.returncode or 'PASS nonblocking' not in result.stdout or errors:
                raise RuntimeError('Socket probe failed: '+repr((result.returncode,errors)))
        finally:
            listener.close()

if __name__=='__main__':main()
