# -*- coding: utf-8 -*-
"""
Implementation of CoLaB specific functionality.

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

from .ColaBase import ColaBase


class ColaB(ColaBase):
    """Holds all COLA B specific attributes and methods"""
    PROTOCOL_Name_STR = "ColaB"
    HEADER = struct.Struct('>ccc')  # old name: _COLAB_HEADER
    DEFAULT_PORT = 2112

    @staticmethod
    def generatePayload(cmd, mode, payload):
        if (not isinstance(cmd, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        if (not isinstance(mode, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        if (not isinstance(payload, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        return ColaB.HEADER.pack(b's', cmd, mode) + payload

    def extractData(self, packet):
        """Extracts data from a received Cola B packet
        :param packet
        :rtype tuple"""
        packetChecksum = bytes([packet[-1]])
        packet = packet[:-1]  # one byte for checksum, see cola spec
        checksum = ColaBase.generateChecksum(packet)
        if checksum != packetChecksum:
            raise RuntimeError(
                "Wrong telegram checksum. Expected: 0x{:02X}, received: 0x{:02X}".format(checksum, packetChecksum))
        startS, cmd, mode = ColaB.HEADER.unpack_from(packet)
        packet = packet[ColaB.HEADER.size:]
        if startS != b's':
            raise RuntimeError(
                "malformed response packet, preceeding 's' missing, got {!r} instead".format(startS))
        return cmd, mode, packet

    def generateChecksum(self, bStr):
        super().generateChecksum(bStr)

    # old name: sendCoLaB
    def send(self, sopas_socket, cmd, mode, payload, reqId=None, sessionId=None):
        msg = self.generatePayload(cmd, mode, payload)
        msg = self.encodeFraming(msg)
        # add one byte for checksum, see cola spec
        payload = self.sendToDevice(sopas_socket, msg, extra_bytes=1)
        return self.extractData(payload)
