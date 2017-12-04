#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import hashlib
import json
import os
import subprocess
import threading
import time

import idc

from aaf import utils
from aaf.debug import ResumeDebugHook
from aaf.debug import JDWP_PORT
from aaf.utils import fn_timer


class AndroidAttacher(object):
    def __init__(self, wrapper, utilsJar, config_file):
        self.packageName = None
        self.launchActivity = None
        self.android_server = None
        self.device = None
        self.adb = wrapper
        self.utilsJar = utilsJar
        self.config_file = config_file
        self.debugProcessName = None
        if hasattr(idc, "idadir"):
            # ida 7.0
            self.bindir = os.path.abspath(idc.idadir() + "/dbgsrv")
        else:
            import idaapi
            self.bindir = os.path.abspath(idaapi.get_idcpath() + "/../dbgsrv")

    def load_config(self):
        try:
            with open(self.config_file, "r") as f:
                return json.load(f, encoding="UTF-8")
        except:
            return {}

    def save_config(self, obj):
        try:
            with open(self.config_file, "w") as f:
                json.dump(obj, f, encoding="UTF-8", ensure_ascii=False)
        except:
            pass

    @fn_timer
    def _chooseDevice(self):
        self.device = self.adb.chooseDevice(self.device)
        print 'Using device %s' % self.device

    @fn_timer
    def _getPid(self, with_service=True):
        pids = []
        processes = []
        ps = self.adb.call(['shell', 'ps']).splitlines()
        for x in ps:
            xs = x.split()
            if 'S' in xs or 'T' in xs:
                for process in xs:
                    if (with_service and process.startswith(self.packageName)) or self.packageName == process:
                        g = (col for col in xs if col.isdigit())
                        pids.append(int(next(g)))
                        processes.append(process)
                        break

        # print "getPid %s, with_service=%s" % (names, with_service)
        if len(pids) == 0:
            return None, None
        if len(processes) == 1 and processes[0] == self.packageName:
            return pids[0], self.packageName

        if self.debugProcessName is not None:
            for i, process in enumerate(processes):
                if self.debugProcessName == process:
                    return pids[i], process

        pid, process = utils.ChooserForm("Choose process", processes, values=pids, cancel="Refresh").choose()
        if pid is None:
            return None, None

        if self.debugProcessName != process:
            self.debugProcessName = process

        return pid, process

    @fn_timer
    def _launch(self, debug):
        start = time.time()
        idc.Message('Launching %s/%s... ' % (self.packageName, self.launchActivity))

        args = ['shell', 'am', 'start', '-n', self.packageName + '/' + self.launchActivity, '-W']
        if debug:
            args.append("-D")

        proc = self.adb.call(args, stderr=subprocess.PIPE, async=True, preexec_fn=utils.androidServerPreExec)

        def watchdog():
            time.sleep(15)
            if proc.poll() is None:  # still running
                proc.terminate()

        (threading.Thread(target=watchdog)).start()

        for _ in range(50):
            pid, _ = self._getPid(with_service=False)
            if pid is not None:
                break
            time.sleep(0.2)
        print "Done in %s seconds" % (time.time() - start)

    @fn_timer
    def _attach(self, debug):
        pid, process = self._getPid(with_service=True)
        if pid:
            self.attach_app(pid, process, debug)
            return

        for _ in range(10):
            self._launch(debug)
            pid, process = self._getPid(with_service=True)
            if pid:
                self.attach_app(pid, process, debug)
                return

        raise StandardError("Error attach %s/%s." % (self.packageName, self.launchActivity))

    @fn_timer
    def attach_app(self, pid, process, debug):
        idc.LoadDebugger("armlinux", use_remote=1)
        idc.SetRemoteDebugger("localhost", "", self.port)
        status = idc.AttachProcess(pid, -1)
        if status == 1:
            print 'Attaching process %s[%s]... Done' % (process, pid)

            if debug:
                try:
                    self.adb.forward('tcp:' + str(JDWP_PORT) , 'jdwp:' + str(pid))
                    self.dbg_hook = ResumeDebugHook()
                    self.dbg_hook.hook()
                except BaseException, e:
                    print e
        else:
            print 'Attaching process %s[%s]... Failed: %s' % (process, pid, status)

    def _chooseLaunchActivity(self, packageName):
        aaf_utils = "/data/local/tmp/aaf_utils.jar"
        # print "Pushing utils.jar to device: %s" % aaf_utils
        self.adb.push(self.utilsJar, aaf_utils)
        out = self.adb.call(['shell', 'su', '-c',
                             '"dalvikvm -cp ' + aaf_utils + ' com.android.internal.util.WithFramework com.fuzhu8.aaf.GetMainActivity ' + packageName + '"'])
        resp = json.loads(out)
        if resp["code"] != 0:
            raise StandardError(resp["msg"])
        main = utils.decode_list(resp["main"])
        if len(main) == 1:
            return main[0]
        activities = utils.decode_list(resp["activities"])
        if len(activities) == 1:
            return activities[0]
        activity, _ = utils.ChooserForm("Choose activity", activities).choose()
        return activity

    @fn_timer
    def _startAndroidServer(self, idaDebugPort):
        global androidServerSuOut
        global port

        ida_port = '-p' + str(idaDebugPort)
        ps = self.adb.call(['shell', 'ps']).splitlines()
        for proc in [x.split() for x in ps if 'android_server' in x]:
            pid = next((col for col in proc if col.isdigit()))
            cmdline = self.adb.call(['shell', 'cat', '/proc/' + pid + '/cmdline']).split('\0')
            if ida_port not in cmdline:
                continue
            self.adb.call(['shell', 'su', '-c', '"kill -9 ' + pid + '"'])

        localServerPath = os.path.join(self.bindir, 'android_server')
        androidServerPath = '/data/local/tmp/android_server'
        remote = self.adb.call(["shell", "md5", androidServerPath]).split()[0]
        md5 = hashlib.md5()
        with open(localServerPath, "r") as f:
            while True:
                strRead = f.read(1024)
                if not strRead:
                    break
                md5.update(strRead)

        if md5.hexdigest() != remote:
            print "Pushing android_server to device: %s" % androidServerPath
            self.adb.push(localServerPath, androidServerPath)
            self.adb.call(['shell', 'chmod', '755', androidServerPath])

        args = [ida_port]

        @fn_timer
        def runAndroidServer(args):  # returns (proc, port, stdout)
            # print "runAndroidServer:", args
            proc = self.adb.call(args, stderr=subprocess.PIPE, async=True, preexec_fn=utils.androidServerPreExec)
            need_watchdog = True

            def watchdog():
                time.sleep(180) # 3 minutes
                if need_watchdog and proc.poll() is None:  # still running
                    proc.terminate()

            (threading.Thread(target=watchdog)).start()

            # we have to find the port used by android_server from stdout
            # while this complicates things a little, it allows us to
            # have multiple android_servers running

            # Listening on port #23946...
            # Listening on 0.0.0.0:23946...
            out = []
            line = ' '
            while line:
                try:
                    line = proc.stdout.readline()
                    # words = line.split()
                    # print "line:", line, "words:", words
                    out.append(line.rstrip())
                    if 'android_server terminated by' in line:
                        break
                    if 'Listening' not in line:
                        time.sleep(0.1)
                        continue

                    if '#' in line:
                        start_index = line.index("#")
                    elif ':' in line:
                        start_index = line.index(":")
                    else:
                        print "parse line failed: ", line
                        continue
                    end_index = line.index("...")
                    port = line[start_index + 1: end_index]

                    if not port.isdigit():
                        print "parse failed: port=", port, ", line=", line
                        continue
                    need_watchdog = False
                    return (proc, port, out)
                except BaseException, e:
                    print e
            # not found, error?
            need_watchdog = False
            return (None, None, out)

        # can we run as root?
        androidServerProc = None

        '''
        if not androidServerProc:
            idc.Message('as non-root... ')
            androidServerArgs = ['shell', 'run-as', pkg, androidServerPath]
            androidServerArgs.extend(args)
            (androidServerProc, port, androidServerRunAsOut) = runAndroidServer(androidServerArgs)
    
        if not androidServerProc:
            idc.Message('in pkg dir... ')
            pkgAndroidServerPath = '/data/data/' + pkg + '/files/android_server'
            self.adb.call(['shell', 'run-as', pkg, 'cp', androidServerPath, pkgAndroidServerPath])
            self.adb.call(['shell', 'run-as', pkg, 'chmod', '755', pkgAndroidServerPath])
            androidServerArgs = ['shell', 'run-as', pkg, pkgAndroidServerPath] + args
            (androidServerProc, port, androidServerPkgRunAsOut) = runAndroidServer(androidServerArgs)
        '''

        if not androidServerProc:
            idc.Message('as root... ')
            (androidServerProc, port, androidServerSuOut) = runAndroidServer(
                ['shell', 'su', '-c', '"' + " ".join([androidServerPath] + args) + '"'])

        '''
        if not androidServerProc:
            idc.Message('in pkg dir... ')
            (androidServerProc, port, androidServerPkgSuOut) = runAndroidServer(['shell', 'su', '-c', '"' + " ".join([pkgAndroidServerPath] + args) + '"'])
        '''

        if not androidServerProc:
            '''
            print ''
            print '"run-as" output:'
            print ' ' + '\n '.join([s for s in androidServerRunAsOut if s]).replace('\0', '')
            print '"run-as pkg" output:'
            print ' ' + '\n '.join([s for s in androidServerPkgRunAsOut if s]).replace('\0', '')
            '''
            print '"su -c" output:'
            print ' ' + '\n '.join([s for s in androidServerSuOut if s]).replace('\0', '')
            '''
            print '"su -c pkg" output:'
            print ' ' + '\n '.join([s for s in androidServerPkgSuOut if s]).replace('\0', '')
            if any('not executable: magic' in s for s in (androidServerRunAsOut + androidServerPkgRunAsOut + androidServerSuOut + androidServerPkgSuOut)):
                print '\n********'
                print '* Your device platform is not supported by this android_server'
                print '********\n'
            '''
            raise StandardError('failed to run android_server')

        self.port = int(port)
        self.android_server = androidServerProc

        # forward the port that android_server gave us
        self.adb.forward('tcp:' + port, 'tcp:' + port)
        print 'Done'

    @fn_timer
    def attach(self, arg):
        try:
            import idaapi
            if idaapi.is_debugger_on():
                print "Already in debug mode."
                return

            is_running = self.android_server is not None and self.android_server.poll() is None
            if self.device is None or not is_running:
                self._chooseDevice()

            config = self.load_config()
            av = utils.AttachView(self.device.getPackageNames(),
                                  config["packageName"] if config.has_key("packageName") else "")
            ret = av.show(config["idaDebugPort"] if config.has_key("idaDebugPort") else 23946,
                          config["debug"] if config.has_key("debug") else False)
            if not ret:
                return
            (packageName, idaDebugPort, debug) = ret

            if idaDebugPort < 1024:
                print "Attach %s failed with ida debug port: %s" % (packageName, idaDebugPort)
                return
            self.save_config({"packageName": packageName, "idaDebugPort": idaDebugPort, "debug": debug})

            if self.launchActivity is None or self.packageName != packageName:
                self.launchActivity = self._chooseLaunchActivity(packageName)

            self.packageName = packageName

            if not self.launchActivity:
                return

            print "Request attach: %s with arg %s" % (packageName, arg)

            if is_running:
                self._attach(debug)
                return

            self._startAndroidServer(idaDebugPort)
            self._attach(debug)
        except BaseException, e:
            if self.android_server and self.android_server.poll() is None:
                self.android_server.terminate()
                print 'Terminated android_server.'
                self.android_server = None

            print e
            # raise
