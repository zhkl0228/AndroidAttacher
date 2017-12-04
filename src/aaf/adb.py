#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import subprocess
from aaf import utils


def checkAdb(path):
    kw = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE}
    kw = utils.processWindows(**kw)
    cmd = [path, "version"]
    try:
        p = subprocess.Popen(cmd, **kw)
        out = p.communicate()[0]
        if p.returncode != 0:
            return False

        return "version" in out
    except:
        return False


class Device(object):
    def __init__(self, serial, model):
        self.serial = serial
        self.model = model
        self.pkgs = None

    def __str__(self):
        return self.model

    def getApkPath(self, packageName):
        return self.pkgs[packageName]

    def getPackageNames(self):
        return self.pkgs.keys()

    def setPackages(self, pkgs):
        self.pkgs = pkgs


class AdbWrapper(object):
    def __init__(self, adb_path):
        self.adb_path = None
        self.adb_device = None

        if checkAdb("adb"):
            self.adb_path = "adb"
            return

        if adb_path and checkAdb(adb_path):
            self.adb_path = adb_path
            return

        try:
            import psutil
            for p in psutil.process_iter():
                try:
                    if "tcp:5037" in p.cmdline():
                        adb_path = p.exe()
                        if checkAdb(adb_path):
                            self.adb_path = adb_path
                            return
                except:
                    pass
        except:
            pass

        raise StandardError("Can't execute adb: " + str(adb_path))

    def call(self, args, **kw):
        kw = utils.processWindows(**kw)

        cmd = [self.adb_path]
        device = self.adb_device
        if device:
            cmd.extend(["-s", device.serial])
        cmd.extend(args)
        async = False
        if 'async' in kw:
            async = kw['async']
            del kw['async']
        if 'stdin' not in kw:
            kw['stdin'] = subprocess.PIPE
        if 'stdout' not in kw:
            kw['stdout'] = subprocess.PIPE
        try:
            adb = subprocess.Popen(cmd, **kw)
            if async:
                return adb
            out = adb.communicate()[0]
        except:
            raise
        if adb.returncode != 0:
            raise StandardError('adb returned exit code ' + str(adb.returncode) + ' for arguments ' + str(args))
        return out

    def getDevices(self):
        devices = {}
        for line in self.call(['devices', '-l']).splitlines():
            try:
                import re
                pattern = re.compile(r"(\S+)\s+device.+model:(.+)\s+device")
                parts = pattern.findall(line)
                if len(parts) != 1:
                    continue
                serial, model = parts[0]
                devices[serial] = serial + '[' + model + ']'
            except:
                pass
        return devices

    def chooseDevice(self, cache):
        # identify device
        devices = self.getDevices()

        if not devices:
            raise StandardError(' ADB: no device')

        if self.adb_device is not None and self.adb_device.serial not in devices:
            print 'Device (%s) is not connected' % self.adb_device

        serial = None
        # use only device
        if len(devices) == 1:
            serial = devices.keys()[0]
        # otherwise, let user decide
        while not serial in devices:
            serial, _ = utils.ChooserForm("Choose device", devices.values(), values=devices.keys()).choose()

        if cache is not None and serial == cache.serial:
            self.adb_device = cache
        else:
            self.adb_device = Device(serial, devices[serial])
            self.adb_device.setPackages(self._getPackageApk())
        return self.adb_device

    def _getPackageApk(self):
        ret = {}
        devicePackages = self.call(['shell', 'pm', 'list', 'packages', '-f', "-3"])
        if not devicePackages.strip():
            return ret
        for devicePackage in (l.strip() for l in devicePackages.splitlines()):
            if not devicePackage:
                continue
            # devicePackage has the format 'package:/data/app/pkg.apk=pkg'
            devicePackage = devicePackage.partition('=')
            ret[devicePackage[2]] = devicePackage[0].partition(':')[2]
        return ret

    def pull(self, src, dest):
        params = ['pull']
        if isinstance(src, list):
            params.extend(src)
        else:
            params.append(str(src))
        params.append(dest)
        self.call(params, stderr=subprocess.PIPE)

    def push(self, src, dest):
        params = ['push']
        if isinstance(src, list):
            params.extend(src)
        else:
            params.append(str(src))
        params.append(dest)
        self.call(params, stderr=subprocess.PIPE)

    def pathExists(self, path):
        # adb shell doesn't seem to return error codes
        out = self.call(['shell', 'ls "' + path + '" echo $?'], stderr=subprocess.PIPE)
        return int(out.splitlines()[-1]) == 0

    def forward(self, from_port, to_port):
        self.call(['forward', from_port, to_port])
