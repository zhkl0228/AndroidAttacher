#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import idaapi
import idc
import time
import threading

from jdwp import JDWPClient

JDWP_PORT=8700


class ResumeDebugHook(idaapi.DBG_Hooks):

    def __init__(self):
        idaapi.DBG_Hooks.__init__(self)

    def dbg_process_attach(self, *args):
        def watchdog():
            while True:
                process_state = idaapi.get_process_state()
                if process_state == idc.DSTATE_RUN:
                    self._resume_jdb()
                    break
                elif process_state == idc.DSTATE_NOTASK:
                    break
                else:
                    time.sleep(0.5)
            self.unhook()
        (threading.Thread(target=watchdog)).start()

    def dbg_process_detach(self, *args):
        self.unhook()

    def dbg_process_exit(self, *args):
        self.unhook()

    def _resume_jdb(self):
        jdwp = JDWPClient(host="127.0.0.1", port=JDWP_PORT)
        try:
            jdwp.start()
            jdwp.resumevm()
            print "Try resume jdwp: %s" % jdwp.version
            time.sleep(5)
        except BaseException, e:
            pass
        finally:
            jdwp.leave()
