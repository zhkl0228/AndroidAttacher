#!/usr/bin/env python
# ! -*- coding: utf-8 -*-
#
# code from Universal JDWP shellifier: https://github.com/IOActive/jdwp-shellifier
#

import struct
import time
import socket

################################################################################
#
# JDWP protocol variables
#
HANDSHAKE                 = "JDWP-Handshake"

REPLY_PACKET_TYPE         = 0x80

VERSION_SIG               = (1, 1)
IDSIZES_SIG               = (1, 7)
RESUMEVM_SIG              = (1, 9)
STRINGVALUE_SIG           = (10, 1)

################################################################################
#
# JDWP client class
#
class JDWPClient(object):

    def __init__(self, host, port):
        self.socket = None
        self.host = host
        self.port = port
        self.methods = {}
        self.fields = {}
        self.id = 0x01

    def create_packet(self, cmdsig, data=""):
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        pkt = struct.pack(">IIccc", pktlen, self.id, chr(flags), chr(cmdset), chr(cmd))
        pkt += data
        self.id += 2
        return pkt

    def read_reply(self):
        header = self.socket.recv(11)
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)

        if flags == chr(REPLY_PACKET_TYPE):
            if errcode:
                raise Exception("Received #0x%x errcode %d" % (id, errcode))

        buf = ""
        while len(buf) + 11 < pktlen:
            data = self.socket.recv(1024)
            if len(data):
                buf += data
            else:
                time.sleep(0.1)
        return buf

    def start(self):
        self.handshake(self.host, self.port)
        self.idsizes()
        self.getversion()

    def handshake(self, host, port):
        s = socket.socket()
        try:
            s.connect( (host, port) )
        except socket.error as msg:
            raise Exception("Failed to connect: %s" % msg)

        s.send( HANDSHAKE )

        if s.recv( len(HANDSHAKE) ) != HANDSHAKE:
            raise Exception("Failed to handshake")
        else:
            self.socket = s

    def readstring(self, data):
        size = struct.unpack(">I", data[:4])[0]
        return data[4:4+size]

    def solve_string(self, objId):
        self.socket.sendall( self.create_packet(STRINGVALUE_SIG, data=objId) )
        buf = self.read_reply()
        if len(buf):
            return self.readstring(buf)
        else:
            return ""

    def parse_entries(self, buf, formats, explicit=True):
        entries = []
        index = 0


        if explicit:
            nb_entries = struct.unpack(">I", buf[:4])[0]
            buf = buf[4:]
        else:
            nb_entries = 1

        for i in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    data[name] = int(struct.unpack(">Q",buf[index:index+8]) [0])
                    index += 8
                elif fmt == "I" or fmt == 4:
                    data[name] = int(struct.unpack(">I", buf[index:index+4])[0])
                    index += 4
                elif fmt == 'S':
                    l = struct.unpack(">I", buf[index:index+4])[0]
                    data[name] = buf[index+4:index+4+l]
                    index += 4+l
                elif fmt == 'C':
                    data[name] = ord(struct.unpack(">c", buf[index])[0])
                    index += 1
                elif fmt == 'Z':
                    t = ord(struct.unpack(">c", buf[index])[0])
                    if t == 115:
                        s = self.solve_string(buf[index+1:index+9])
                        data[name] = s
                        index+=9
                    elif t == 73:
                        data[name] = struct.unpack(">I", buf[index+1:index+5])[0]
                        buf = struct.unpack(">I", buf[index+5:index+9])
                        index=0

                else:
                    raise Exception("JDWP parse_entries Error")

            entries.append( data )

        return entries

    def idsizes(self):
        self.socket.sendall( self.create_packet(IDSIZES_SIG) )
        buf = self.read_reply()
        formats = [ ("I", "fieldIDSize"), ("I", "methodIDSize"), ("I", "objectIDSize"),
                    ("I", "referenceTypeIDSize"), ("I", "frameIDSize") ]
        for entry in self.parse_entries(buf, formats, False):
            for name, value  in entry.iteritems():
                setattr(self, name, value)

    def leave(self):
        if self.socket is not None:
            self.socket.close()

    def getversion(self):
        self.socket.sendall( self.create_packet(VERSION_SIG) )
        buf = self.read_reply()
        formats = [ ('S', "description"), ('I', "jdwpMajor"), ('I', "jdwpMinor"),
                    ('S', "vmVersion"), ('S', "vmName"), ]
        for entry in self.parse_entries(buf, formats, False):
            for name,value  in entry.iteritems():
                setattr(self, name, value)

    @property
    def version(self):
        return "%s - %s" % (self.vmName, self.vmVersion)

    def resumevm(self):
        self.socket.sendall( self.create_packet( RESUMEVM_SIG ) )
        self.read_reply()
