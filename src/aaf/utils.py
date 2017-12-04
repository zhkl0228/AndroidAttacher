#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import platform
import subprocess
import time
import functools

from idaapi import Form

CALC_EXEC_TIME = False


class ChooserForm(Form):
    def __init__(self, title, labels, values=None, cancel="Cancel", index=0):
        Form.__init__(self, ("STARTITEM 0\n"
                             "BUTTON YES* OK\n"
                             "BUTTON CANCEL " + cancel + "\n" + title + "\n"
                                                                "\n"
                                                                "<Please select :{values}>\n"),
                      {"values": Form.DropdownListControl(items=labels, readonly=True, selval=index)})
        self.labels = labels
        self.cvs = values if values is not None else labels

    def choose(self):
        self.Compile()
        if self.Execute() != 1:
            return None, None
        return self.cvs[self.values.value], self.labels[self.values.value]

    def OnButtonNop(self, code=0):
        pass


class AttachView(Form):
    def __init__(self, names, packageName):
        idx = 0
        if packageName and packageName in names:
            idx = names.index(packageName)
        Form.__init__(self, ("STARTITEM 0\n"
                             "BUTTON YES* Attach\n"
                             "BUTTON CANCEL Cancel\n"
                             "Attach android application\n"
                             "\n"
                             "<##   Package Name:{names}>\n"
                             "<## IDA Debug Port:{idaDebugPort}>\n"
                             "Launch Options"
                             " <Debug Mode:{debug}>{launchOptions}>\n"
                             "\n"
                             ), {'names': Form.DropdownListControl(items=names, readonly=True, selval=idx),
                                 'idaDebugPort': Form.NumericInput(tp=Form.FT_DEC),
                                 "launchOptions": Form.ChkGroupControl(["debug"])})
        self.pns = names
        self.pn = packageName

    def show(self, idaDebugPort, debug):
        self.Compile()
        self.idaDebugPort.value = idaDebugPort
        self.debug.checked = debug
        if self.Execute() != 1:
            return
        return (self.pns[self.names.value], self.idaDebugPort.value, self.debug.checked)

    def OnButtonNop(self, code=0):
        pass


def isWindows():
    return "windows" in platform.system().lower()


def processWindows(**kw):
    if isWindows():
        if "preexec_fn" in kw:
            kw.pop("preexec_fn")
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags = subprocess.CREATE_NEW_CONSOLE | subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        kw["startupinfo"] = startupinfo
    return kw


def fn_timer(function):
    @functools.wraps(function)
    def function_timer(*args, **kw):
        if not CALC_EXEC_TIME:
            return function(*args, **kw)

        start = time.time()
        ret = function(*args, **kw)
        print "Total time running %s: %s seconds." % (function.func_name, time.time() - start)
        return ret

    return function_timer


def getIdaArchitecture():
    import idaapi
    inf = idaapi.get_inf_structure()
    name = inf.procName
    ret = []
    for x in name:
        if ord(x) == 0:
            break
        else:
            ret.append(x)
    return "".join(ret).lower()


# run this after fork() and before exec(android_server)
# so 'adb shell android_server' doesn't get utils's signals
def androidServerPreExec():
    import os
    os.setpgrp()


def decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        rv.append(item)
    return rv
