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
    def __init__(self, dev, pkgs):
        self.dev = dev
        self.pkgs = pkgs

    def __str__(self):
        return self.dev

    def getApkPath(self, packageName):
        return self.pkgs[packageName]

    def getPackageNames(self):
        return self.pkgs.keys()


class AdbWrapper(object):
    def __init__(self, adb_path):
        self.adb_path = None
        self.adb_device = ""

        if adb_path and checkAdb(adb_path):
            self.adb_path = adb_path
            return

        if checkAdb("adb"):
            self.adb_path = "adb"
            return

        raise StandardError("Can't execute adb: " + str(adb_path))

    def call(self, args, **kw):
        kw = utils.processWindows(**kw)

        cmd = [self.adb_path]
        dev = self.adb_device
        if dev:
            cmd.extend(["-s", dev])
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
        devs = []
        for sdev in self.call(['devices']).splitlines():
            devparts = sdev.partition('\t')
            if devparts[2] != 'device':
                continue
            devs.append(devparts[0].strip())
        return devs

    def chooseDevice(self, cache):
        # identify device
        devs = self.getDevices()

        if not devs:
            raise StandardError(' ADB: no device')

        dev = self.adb_device
        if dev and dev not in devs:
            print 'Device (%s) is not connected' % dev
        # use only device
        if len(devs) == 1:
            dev = devs[0]
        # otherwise, let user decide
        while not dev in devs:
            dev = utils.ChooserForm("Choose device", devs).choose()
        if self.adb_device != dev:
            self.adb_device = dev

        if cache and dev == cache.dev:
            return cache
        return Device(dev, self._getPackageApk())

    def _getPackageApk(self):
        ret = {}
        devpkgs = self.call(['shell', 'pm', 'list', 'packages', '-f', "-3"])
        if not devpkgs.strip():
            return ret
        for devpkg in (l.strip() for l in devpkgs.splitlines()):
            if not devpkg:
                continue
            # devpkg has the format 'package:/data/app/pkg.apk=pkg'
            devpkg = devpkg.partition('=')
            ret[devpkg[2]] = devpkg[0].partition(':')[2]
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
