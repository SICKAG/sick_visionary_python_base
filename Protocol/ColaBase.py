# -*- coding: utf-8 -*-
"""
Implementation of CoLa common functionality.

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
import logging
from abc import abstractmethod, ABC

from .ColaErrors import ColaErrors

logger = logging.getLogger(__name__)


class ColaBase(ABC):
    # start sequence of the CoLa protocol
    START_STX = b'\x02\x02\x02\x02'

    @abstractmethod
    def send(*args):
        raise NotImplementedError(
            "Method must be implemented in the subclasses!")

    # old name: encode_framing
    def encodeFraming(self, payload):
        """the binary framing used to serialize the commands"""
        if not isinstance(payload, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        return ColaBase.START_STX + struct.pack('>I', len(payload)) + payload + ColaBase.generateChecksum(payload)

    @abstractmethod
    def extractData(self, *data):
        raise NotImplementedError(
            "Method must be implemented in the subclasses!")

    @staticmethod
    def recvResponse(sopas_socket, extra_bytes):
        header = sopas_socket.recv(8)  # minimum header

        if ColaBase.START_STX != header[:4]:
            raise RuntimeError("Could not find start of framing")

        payloadLength, = struct.unpack_from('>I', header, 4)
        payloadLength += extra_bytes

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("received header (8 bytes): %s" %
                         ColaBase.to_hex(header))
            logger.debug("length of %i bytes expected" % payloadLength)

        toread = payloadLength
        data = bytearray(toread)
        view = memoryview(data)

        while toread:
            nBytes = sopas_socket.recv_into(view, toread)
            if nBytes == 0:
                # premature end of connection
                raise RuntimeError(
                    "received {} but requested {} bytes".format(len(data) - len(view), payloadLength))
            view = view[nBytes:]
            toread -= nBytes

        payload = bytes(data)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("received %i bytes payload" % len(payload))
            logger.debug("payload is: %s" % ColaBase.to_hex(payload))

        return payload

    # old name: chksum_cola
    @staticmethod
    def generateChecksum(bStr):
        """ Calculate CoLa checksum.
        The checksum is built by exclusive ORing all bytes beginning after the
        length indication. The checksum is one byte and it is placed at the end of
        the frame.
        """
        if not isinstance(bStr, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        chksum = 0
        for x in bytearray(bStr):
            chksum ^= x
        return bytes([chksum])

    @staticmethod
    def to_hex(bStr):
        """ just to produce a readable output of the device responses """
        if not isinstance(bStr, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        fStr = '==> hexDump\n'
        cnt = 0
        for b in bytearray(bStr):
            if cnt == 0:
                fStr += '    '
            cnt += 1
            fStr += '{:02X} '.format(b)
            if cnt % 4 == 0:
                fStr += ' '
            if cnt % 16 == 0:
                fStr += '\n'
                cnt = 0
        if cnt != 0:
            fStr += '\n'
        fStr += 'hexDump <=='
        return fStr

    @staticmethod
    def sendToDevice(sopas_socket, message, extra_bytes):
        """ Sends a given message to the device and return the response """
        if not isinstance(message, bytes):
            raise RuntimeError(
                "Invalid protocol string! String was {} and not bytes.".format(type(message)))
        logger.debug("Sending %d bytes to device: %s" %
                     (len(message), ColaBase.to_hex(message)))
        sopas_socket.send(message)
        return ColaBase.recvResponse(sopas_socket, extra_bytes)

    def check_response_payload(self, name, cmd, recvCmd, recvMode, payload):
        # expected response command code
        if cmd == b'M':
            # synchronous methods returns AN on success
            expectedCmd = b'A'
            expectedMode = b'N'
        else:
            expectedCmd = cmd
            expectedMode = b'A'

        if recvCmd != expectedCmd:
            if recvCmd == b'F':
                errorNumber, = struct.unpack_from('>H', payload)
                self.raise_cola_error(errorNumber)
            else:
                raise RuntimeError(
                    "unexpcted response packet, expected command {!r}; got {!r}".format(expectedCmd, recvCmd))

        if recvMode != expectedMode:
            raise RuntimeError(
                "invalid response packet, expected answer; got: {!r}{!r}".format(recvCmd, recvMode))

        # check for space between mode and name
        if payload.find(b' ') != 0:
            raise RuntimeError(
                "malformed package, expected space after mode, but got {}{}{!r}".format(recvCmd, recvMode, payload[0]))
        payload = payload[1:]

        # check if received name matches, maximum name length assumed to be 128
        nameEndIdx = payload[:128].find(b' ')

        if nameEndIdx == 0:
            raise RuntimeError(
                "malformed package, got empty name {!r}{!r}".format(recvCmd, recvMode))

        if nameEndIdx > 0:
            recvName = payload[:nameEndIdx]
            payload = payload[nameEndIdx + 1:]
        else:
            recvName = payload.tobytes()
            payload = bytes()

        if recvName != name:
            raise RuntimeError(
                "cmd name {!r} and response name {!r} differ".format(name, recvName))

        return payload

    @staticmethod
    def raise_cola_error(error_code):
        return ColaErrors.get_error_message(error_code)
