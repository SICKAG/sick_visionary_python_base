# -*- coding: utf-8 -*-
"""
Implementation of the Streaming API channel.

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

import logging
import select
import socket
import struct
import sys
import time

logger = logging.getLogger(__name__)


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


class Streaming:

    """ All methods that use the streaming channel. """

    def __init__(self, ipAddress='192.168.1.10', tcpPort=2114):
        self.ipAddress = ipAddress
        self.tcpPort = tcpPort
        self.sock_stream = None

    def _read(self, nBytes):
        """ Read exactly nBytes from the streaming socket and return the number of bytes read.
            If the peer hung-up (recv returned an empty string), we return everything read so far (thus less than nBytes).
        """
        buffer = bytes()
        lenBuffer = 0
        while lenBuffer < nBytes:
            data = self.sock_stream.recv(
                # recv(x) receives maximum (!!) x bytes! No guarante that we receive all required bytes!
                nBytes - lenBuffer)
            lenReceived = len(data)
            if lenReceived == 0:
                break

            # buffer has to be concatinated (appended) with the bytes object (data)
            buffer += data
            lenBuffer += lenReceived
        return buffer

    ''' Opens the streaming channel. '''

    def openStream(self):
        logger.info("Opening streaming socket..."),
        self.sock_stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_stream.settimeout(5)
        try:
            self.sock_stream.connect((self.ipAddress, self.tcpPort))
        except socket.error as err:
            print("Error on connecting to %s:%d: %s" %
                  (self.ipAddress, self.tcpPort, err))
            logger.error("Error on connecting to %s:%d: %s" %
                         (self.ipAddress, self.tcpPort, err))
            sys.exit(2)
        logger.info("...done.")

    def closeStream(self):
        """ Closes the streaming channel. """
        if self.sock_stream is not None:
            logging.info("Closing streaming connection..."),
            self.sock_stream.close()
            logging.info("...done.")

    def sendBlobRequest(self):
        """ Sending a blob request. """
        MSG_BLREQ_TX = b'BlbReq'

        logger.debug("Sending BlbReq: %s" % (to_hex(MSG_BLREQ_TX)))
        self.sock_stream.send(MSG_BLREQ_TX)

    def fileno(self):
        """ Make our stream compatible with select"""
        return self.sock_stream.fileno()

    @staticmethod
    def poll(stream_seq, timeout=None):
        """ Polls whether a frame is available on a sequence of streams

        Returns a tuple of
          1. a list of received frames; at the index of a passed stream is the received frame
          2. a list of streams in exceptional state
        or None if there was none"""

        rlist, _, _ = select.select(stream_seq, [], [], timeout)

        frames = []
        for stream in stream_seq:
            if stream in rlist:
                stream.getFrame(peek=True)
                frames.append(stream.frame)
            else:
                frames.append(None)
        return frames

    def getFrame(self, peek=False):
        """ Receives the raw data frame from the device via the streaming channel.

         peek(bool): if True it returns True if no data were found.
        """
        logger.debug('Reading image from stream...')
        self.frame = None  # reset old frame
        self.frame_acq_time_s = None

        keepRunning = True

        BLOB_HEAD_LEN = 11
        try:
            # read exactly the header length!
            header = self._read(BLOB_HEAD_LEN)
            receiveLenth = len(header)
            if receiveLenth < BLOB_HEAD_LEN:
                raise socket.error(
                    "Network connection closed by peer. Receive length is {} and should be {}".format(receiveLenth,
                                                                                                      BLOB_HEAD_LEN))
        except socket.timeout:
            header = None

        if not header:
            if peek:
                return
            raise socket.timeout("BLOB header received a timeout")

        self.frame_acq_time_s = time.time()

        logger.debug("len(header) = %d dump: %s" %
                     (len(header), to_hex(header)))
        assert len(header) == BLOB_HEAD_LEN, "Uh, not enough bytes for BLOB_HEAD_LEN, only %s" % (
            len(header))

        # check if the header content is as expected
        (magicword, pkgLength, protocolVersion, packetType) = \
            struct.unpack('>IIHB', header)
        if magicword != 0x02020202:
            logger.error("Unknown magic word: %0x" % (magicword))
            keepRunning = False
        if protocolVersion != 0x0001:
            logger.error("Unknown protocol version: %0x" % (protocolVersion))
            keepRunning = False
        if packetType != 0x62:
            logger.error("Unknown packet type: %0x" % (packetType))
            keepRunning = False

        if not keepRunning:
            raise RuntimeError('something is wrong with the buffer')

        # -3 for protocolVersion and packetType already received
        # +1 for checksum
        toread = pkgLength - 3 + 1
        logger.debug("pkgLength: %d" % (pkgLength))
        logger.debug("toread: %d" % (toread))

        data = bytearray(len(header) + toread)
        view = memoryview(data)
        view[:len(header)] = header
        view = view[len(header):]
        while toread:
            nBytes = self.sock_stream.recv_into(view, toread)
            if nBytes == 0:
                # premature end of connection
                raise RuntimeError("received {} but requested {} bytes".format(
                    len(data) - len(view), pkgLength))
            view = view[nBytes:]
            toread -= nBytes

        self.frame = data

        frame_acq_stop = time.time()
        self.frame_revc_time_s = (frame_acq_stop - self.frame_acq_time_s)
        logger.info("Receiving took %0.1f ms" %
                    ((self.frame_revc_time_s) * 1000))
        # full frame should be received now
        logger.debug("...done.")
