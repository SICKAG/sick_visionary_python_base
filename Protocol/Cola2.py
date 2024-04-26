# -*- coding: utf-8 -*-
"""
Implementation of CoLa2 specific functionality.

Author: GBC09 / BU05 / SW
SICK AG, Waldkirch
email: techsupport0905@sick.de

Copyright note: Redistribution and use in source, with or without modification, are permitted.

Liability clause: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import struct
import time

from .ColaBase import ColaBase


class Cola2(ColaBase):
    """Holds all COLA 2 specific attributes and methods"""
    PROTOCOL_Name_STR = "Cola2"
    HEADER = struct.Struct('>IHcc')  # old name: _COLA2_HEADER
    DEFAULT_PORT = 2122

    def __init__(self):
        self.sessionId = -1
        self.requestId = 0xFFFF
        self.sessionTimeoutSeconds = 30
        self.lastSendTime = 0

    @staticmethod
    def generatePayload(sessionId, requestId, cmd, mode, payload):
        if (not isinstance(cmd, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        if (not isinstance(mode, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        if (not isinstance(payload, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        return Cola2.HEADER.pack(sessionId, requestId, cmd, mode) + payload

    def extractData(self, packet):
        """Extracts data from a received Cola 2 packet
        :param packet
        :param reqId
        :rtype tuple, format: sessionId, cmd, mode, payload """
        # skip HubCtrl und NoC
        payload = packet[2:]
        recvSessionId, recvReqId, cmd, mode = Cola2.HEADER.unpack_from(payload)
        payload = payload[Cola2.HEADER.size:]
        if recvReqId != self.requestId:
            raise RuntimeError("unexpected response; request ids {} expected, but got {}".format(
                recvReqId, self.requestId))
        if (self.sessionId == 0):
            self.sessionId = recvSessionId
        elif recvSessionId != self.sessionId:
            raise RuntimeError("unexpected response; session ids {} expected, but got {}".format(
                recvSessionId, self.sessionId))

        return cmd, mode, payload

    def generateChecksum(self, bStr):
        return ""

    # old name: addMessageLayer
    def encodeFraming(self, payload):
        """ the binary framing used to serialize the commands """
        if not isinstance(payload, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        # checksum is omitted in CoLa 2
        # HubCntr and NoC are inserted as 0
        return ColaBase.START_STX + struct.pack('>IBB', len(payload) + 2, 0, 0) + payload

    def getSession(self, sopas_socket):
        self.sessionId = 0
        self.requestId = 0xFFFF
        clientID = b'pythonDevice'
        payload = struct.pack(
            '>BH', self.sessionTimeoutSeconds, len(clientID)) + clientID
        cmd, mode, data = self.send(sopas_socket, b'O', b'x', payload)

        if cmd != b'O' or mode != b'A':
            if cmd == b'F' and mode == b'A':
                error_code, = struct.unpack_from('>H', data)
                self.protocol.raise_cola_error(error_code)
            raise RuntimeError(
                "failed to create session, invalid command {!r} and mode {!r}".format(cmd, mode))
        if self.sessionId == 0:
            raise RuntimeError("failed to create session, sessionId was 0")

    # old name: sendCoLa2
    def send(self, sopas_socket, cmd, mode, payload):
        """
        Sends data and automatically creates new CoLa2 session if the previous one timed out.
        """
        if (self.sessionId == -1 or time.time() - self.lastSendTime >= self.sessionTimeoutSeconds):
            self.lastSendTime = time.time()
            self.getSession(sopas_socket)
        self.lastSendTime = time.time()

        # fix: avoid type convertion from UINT16 to UINT32, Header requires only 16bit!
        if self.requestId == 0xFFFF:
            self.requestId = 0
        else:
            self.requestId += 1

        msg = self.generatePayload(
            self.sessionId, self.requestId, cmd, mode, payload)
        msg = self.encodeFraming(msg)

        request_data = self.sendToDevice(sopas_socket, msg, extra_bytes=0)

        return self.extractData(request_data)
