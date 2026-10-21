"""Local fixture for a native probe, executed through the existing t4 runner."""
from pathlib import Path
import os,socket,subprocess,threading,shutil,time
ROOT=Path(__file__).resolve().parents[2]
root=Path('/tmp/helios-review-emulator-root')
shutil.copy2(ROOT/'ktm-distribution/work/sp1/prod/TRAN/lib/Posix',root/'lib/Posix')
shutil.copy2(ROOT/'ktm-distribution/work/compat/bin/io',root/'bin/compat-io')
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(45)
errors=[]
def serve():
    try:
        c,_=listener.accept()
        with c:
            c.settimeout(20);data=b''
            while True:
                b=c.recv(64)
                if not b:break
                data+=b
            assert data==b'request',data
            c.sendall(b'reply')
        c,_=listener.accept()
        with c:
            time.sleep(.2)
            c.shutdown(socket.SHUT_WR)
            time.sleep(.2)
    except Exception as e:errors.append(repr(e))
t=threading.Thread(target=serve,daemon=True);t.start()
env=dict(os.environ,HELIOS_RUN_CON=os.environ.get('HELIOS_RUN_CON','/tmp/helios-fix-emulator.con'),
         HELIOS_RUN_IOSERVER=os.environ.get('HELIOS_RUN_IOSERVER','/tmp/helios-fixes-20261020/ioserver'),
         HELIOS_RUN_T4ARGS='-sm 24')
p=subprocess.run([str(ROOT/'ioserver-linux/helios-run'),'-s8','-t30','-T90','-q',
                  '/helios/bin/compat-io 127.0.0.1 '+str(listener.getsockname()[1])],env=env,capture_output=True,text=True)
print(p.stdout);print(p.stderr)
t.join(2);listener.close()
assert p.returncode==0 and 'PASS nonblocking' in p.stdout,(p.returncode,errors)
assert not errors,errors
