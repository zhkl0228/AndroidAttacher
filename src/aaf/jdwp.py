#!/usr/bin/env python
# ! -*- coding: utf-8 -*-
#
# code from Universal JDWP shellifier: https://github.com/IOActive/jdwp-shellifier
#

import struct
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

HEADER_LENGTH             = 11

################################################################################
#
# JDWP client class
#
class JDWPClient(object):

    def __init__(self, host, port):
        self.socket = None
        self.host = host
        self.port = port
        self.id = 0x01

    def create_packet(self, cmdsig, data=""):
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + HEADER_LENGTH
        packet = struct.pack(">IIccc", pktlen, self.id, chr(flags), chr(cmdset), chr(cmd))
        packet += data
        self.id += 2
        return packet

    def read_reply(self):
        header = self.recvall(HEADER_LENGTH)
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)

        if flags == chr(REPLY_PACKET_TYPE):
            if errcode:
                raise Exception("Received #0x%x errcode %d" % (id, errcode))

        return self.recvall(pktlen - HEADER_LENGTH)

    def start(self):
        self.handshake(self.host, self.port)
        self.getversion()

    def handshake(self, host, port):
        self.socket = socket.socket()
        try:
            self.socket.connect( (host, port) )
        except socket.error as msg:
            raise Exception("JDWP: Failed to connect: %s" % msg)

        self.socket.sendall( HANDSHAKE )
        if self.recvall(len(HANDSHAKE)) != HANDSHAKE:
            raise Exception("JDWP: Failed to handshake")

    def parse_entries(self, buf, formats, explicit=True):
        entries = []
        index = 0

        if explicit:
            nb_entries = struct.unpack(">I", buf[:4])[0]
            buf = buf[4:]
        else:
            nb_entries = 1

        for _ in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    data[name] = int(struct.unpack(">Q",buf[index:index+8])[0])
                    index += 8
                elif fmt == "I" or fmt == 4:
                    data[name] = int(struct.unpack(">I", buf[index:index+4])[0])
                    index += 4
                elif fmt == 'S':
                    len = struct.unpack(">I", buf[index:index+4])[0]
                    data[name] = buf[index+4:index+4+len]
                    index += 4 + len
                elif fmt == 'C':
                    data[name] = ord(struct.unpack(">c", buf[index])[0])
                    index += 1
                else:
                    raise Exception("JDWP parse_entries Error: fmt=%s, name=%s" % (fmt, name))

            entries.append( data )

        return entries

    def leave(self):
        if self.socket is not None:
            self.socket.close()

    def getversion(self):
        self.socket.sendall( self.create_packet(VERSION_SIG) )
        buf = self.read_reply()
        formats = [ ('S', "description"), ('I', "jdwpMajor"), ('I', "jdwpMinor"), ('S', "vmVersion"), ('S', "vmName") ]
        for entry in self.parse_entries(buf, formats, explicit=False):
            for name, value in entry.iteritems():
                setattr(self, name, value)

    @property
    def version(self):
        return "%s-%s" % (self.vmName, self.vmVersion)

    def resumevm(self):
        self.socket.sendall( self.create_packet( RESUMEVM_SIG ) )
        self.read_reply()

    def recvall(self, length):
        buf = ""
        read = 0
        while read < length:
            data = self.socket.recv(length - read)
            if len(data) < 1:
                raise Exception("JDWP EOF")

            read += len(data)
            buf += data
        return buf
