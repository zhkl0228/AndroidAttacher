import idaapi
import utils
import os
import subprocess
import time
import threading
import adb
class DBG_Hook(idaapi.DBG_Hooks):
    def __init__(self):
        idaapi.DBG_Hooks.__init__(self)

    def dbg_process_attach(self, *args):
        def watchdog():
            while idaapi.get_process_state()!=1:
                time.sleep(3)
            self._resume_jdb()
            self.unhook()
            print("unhooked the dbg")
        (threading.Thread(target=watchdog)).start()

    def _resume_jdb(self):
        # if is debug mode,use the jdb to resume the program
        if adb.hasJdb():
           path="jdb"
        else:
            env=os.environ
            java_path=env.get('JAVA_HOME')
            if java_path is None:
                idaapi.warning("can't find JAVA_HOME,please add the JAVA_HOME into environment or resume the program manually")
                return
            path=os.path.join(java_path,"bin","jdb.exe")
            if not os.path.exists(path):
                return
        if utils.isWindows():
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags = subprocess.CREATE_NEW_CONSOLE | subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            proc=subprocess.Popen([path,'-connect','com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700'], stderr=subprocess.PIPE,startupinfo=startupinfo)
        else:
            proc=subprocess.Popen([path,'-connect','com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700'], stderr=subprocess.PIPE)
        print("jdb -connect finished")
        need_watchdog = True
        def watchdog():
            time.sleep(3)
            if need_watchdog and proc.poll() is None: # still running
                proc.terminate()
        (threading.Thread(target=watchdog)).start()