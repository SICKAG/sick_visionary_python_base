# -*- coding: utf-8 -*-
"""
This module handles the incoming data and extracts information from it.

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
import time
from typing import Tuple

from .BinaryParser import BinaryParser
from .ParserHelper import CameraParameters
from .XMLParser import XMLParser
from ..UnitConversion import convertDistanceToMM


class Data:
    """ Gathers methods to handle the raw data. """

    def __init__(self, xmlParser=None, changedCounter=-1, depthmap=None, polarData=None, checksum='E'):
        self.xmlParser = xmlParser
        self.changedCounter = changedCounter
        self.depthmap = depthmap
        self.polarData2D = polarData
        self.checksum = checksum
        self.corrupted = False

        self.parsing_time_s = 0

    def read(self, dataBuffer, convertToMM=True):
        """
        Extracts necessary data segments and triggers parsing of segments. 

        dataBuffer:  The raw data from the device. Obtained for example via getFrame() (Stream.py)
        convertToMM: If this is True, depthmap data is converted to millimeters after reading (can result in floating point values).
                     If this is False, the raw (integer) depth data from the device is used:
                       - Tenth millimeters for Visionary S
                       - Quarter millimeters for Visionary T Mini
                       - Millimeters for Visionary T
        """

        parsing_start_time_s = time.time()

        # first 11 bytes contain some internal definitions
        # code threw following error:
        #   File "..\common\Data.py", line 50, in read
        #     unpack('>IIHB', tempBuffer)
        # TypeError: a bytes-like object is required, not 'str'

        # tempBuffer = dataBuffer[0:11]
        tempBuffer = dataBuffer[0:11]
        (magicword, pkglength, protocolVersion, packetType) = \
            struct.unpack('>IIHB', tempBuffer)
        assert (magicword == 0x02020202)
        logging.debug("Package length: %s", pkglength)
        # expected to be == 1
        logging.debug("Protocol version: %s", protocolVersion)
        logging.debug("Packet type: %s", packetType)  # expected to be  == 98

        # next four bytes an id (should equal 1) and
        # the number of segments (should be 3)
        tempBuffer = dataBuffer[11:15]
        (segid, numSegments) = struct.unpack('>HH', tempBuffer)
        logging.debug("Blob ID: %s", segid)  # expected to be == 1
        # expected to be  == 3
        logging.debug("Number of segments: %s", numSegments)

        # offset and changedCounter, 4 bytes each per segment
        offset = [None] * numSegments
        changedCounter = [None] * numSegments
        tempBuffer = dataBuffer[15:15 + numSegments * 2 * 4]
        for i in range(numSegments):
            index = i * 8
            (offset[i], changedCounter[i]) = \
                struct.unpack('>II', tempBuffer[index:index + 8])
            offset[i] += 11
        # offset in bytes for each segment
        logging.debug("Offsets: %s", offset)
        # counter for changes in the data
        logging.debug("Changed counter: %s", changedCounter)

        # first segment describes the data format in XML
        xmlSegment = dataBuffer[offset[0]:offset[1]]
        logging.debug("The whole XML segment:")
        logging.debug(xmlSegment)
        # second segment contains the binary data
        binarySegment = dataBuffer[offset[1]:offset[2]]

        if (numSegments == 3):
            # numBytes(magicword) = 4, numBytes(pkglength) = 4
            overlaySegment = dataBuffer[offset[2]:pkglength+4+4]
            logging.debug("The whole overlay XML segment:")
            logging.debug(overlaySegment)

        checksum = chr(dataBuffer[pkglength+8])
        if checksum != self.checksum:
            logging.error("Checksum is wrong: %s (expected %s)" %
                          (checksum, self.checksum))  # checksum of whole data
            self.corrupted = True
        else:
            logging.debug("Checksum: %s", checksum)  # checksum of whole data
            self.corrupted = False

        # parsing the XML in order to extract necessary image information
        # only parse if something has changed
        if (self.changedCounter < changedCounter[0]):
            logging.debug("XML did change, parsing started.")
            myXMLParser = XMLParser()
            myXMLParser.parse(xmlSegment)
            self.xmlParser = myXMLParser
            self.changedCounter = changedCounter[0]
        else:
            logging.debug("XML did not change, not parsing again.")
            myXMLParser = self.xmlParser

        myBinaryParser = BinaryParser()

        self.hasDepthMap = False
        self.hasPolar2D = False
        self.hasCartesian = False

        if myXMLParser.hasDepthMap:
            logging.debug("Data contains depth map, reading camera params")
            self.hasDepthMap = True
            self.cameraParams = \
                CameraParameters(width=myXMLParser.imageWidth,
                                 height=myXMLParser.imageHeight,
                                 cam2worldMatrix=myXMLParser.cam2worldMatrix,
                                 fx=myXMLParser.fx, fy=myXMLParser.fy,
                                 cx=myXMLParser.cx, cy=myXMLParser.cy,
                                 k1=myXMLParser.k1, k2=myXMLParser.k2, k3=myXMLParser.k3,
                                 p1=myXMLParser.p1, p2=myXMLParser.p2,
                                 f2rc=myXMLParser.f2rc)

            # extracting data from the binary segment (distance, intensity
            # and confidence).
            if myXMLParser.stereo:
                numBytesDistance = myXMLParser.imageHeight * \
                    myXMLParser.imageWidth * \
                    myXMLParser.numBytesPerZValue
            else:
                numBytesDistance = myXMLParser.imageHeight * \
                    myXMLParser.imageWidth * \
                    myXMLParser.numBytesPerDistanceValue
            numBytesIntensity = myXMLParser.imageHeight * \
                myXMLParser.imageWidth * \
                myXMLParser.numBytesPerIntensityValue
            numBytesConfidence = myXMLParser.imageHeight * \
                myXMLParser.imageWidth * \
                myXMLParser.numBytesPerConfidenceValue

            try:
                numBytesFrameNumber = myXMLParser.numBytesFrameNumber
                numBytesQuality = myXMLParser.numBytesQuality
                numBytesStatus = myXMLParser.numBytesStatus
            except AttributeError:
                numBytesFrameNumber = 0
                numBytesQuality = 0
                numBytesStatus = 0

            logging.info("Reading binary segment...")
            myBinaryParser.getDepthMap(binarySegment,
                                       numBytesFrameNumber,
                                       numBytesQuality,
                                       numBytesStatus,
                                       numBytesDistance,
                                       numBytesIntensity,
                                       myXMLParser.numBytesPerIntensityValue,
                                       numBytesConfidence)
            logging.info("...done.")

            if convertToMM:
                myBinaryParser.depthmap.distance = convertDistanceToMM(
                    myBinaryParser.depthmap.distance, myXMLParser)
            self.depthmap = myBinaryParser.depthmap

        if myXMLParser.hasPolar2DData:
            self.hasPolar2D = True
            if (myXMLParser.hasDepthMap):
                myBinaryParser.getPolar2D(
                    myBinaryParser.remainingBuffer, myXMLParser.numPolarValues)
            else:
                myBinaryParser.getPolar2D(
                    binarySegment, myXMLParser.numPolarValues)
            if hasattr(myBinaryParser, 'polardata'):
                self.polarData2D = myBinaryParser.polardata
            else:
                self.hasPolar2D = False
        elif myXMLParser.hasCartesianData:
            self.hasCartesian = True
            if (myXMLParser.hasDepthMap):
                myBinaryParser.getCartesian(myBinaryParser.remainingBuffer)
            else:
                myBinaryParser.getCartesian(binarySegment)
            if hasattr(myBinaryParser, 'cartesianData'):
                self.cartesianData = myBinaryParser.cartesianData
            else:
                self.hasCartesian = False

        self.parsing_time_s = time.time() - parsing_start_time_s

    def getDecodedTimestamp(self) -> Tuple[int, int, int, int, int, int, int]:
        """
        Decodes the timestamp from the depthmap.

        The timestamp is an integer that needs to be interpreted as a binary number, not a decimal number. It is encoded as follows:
        - 5 unused bits
        - 12 bits for the Year
        - 4 bits for the Month
        - 5 bits for the Day
        - 11 bits for the Timezone
        - 5 bits for the Hour
        - 6 bits for the Minute
        - 6 bits for the Seconds
        - 10 bits for the Milliseconds

        Returns:
            Year, Month, Day, Hour, Minute, Seconds, Milliseconds: Decoded timestamp values.
        """
        if self.depthmap.timestamp is not None:
            YearMask = 0b0000011111111111100000000000000000000000000000000000000000000000
            MonthMask = 0b0000000000000000011110000000000000000000000000000000000000000000
            DayMask = 0b0000000000000000000001111100000000000000000000000000000000000000
            TimezoneMask = 0b0000000000000000000000000011111111111000000000000000000000000000
            HourMask = 0b0000000000000000000000000000000000000111110000000000000000000000
            MinuteMask = 0b0000000000000000000000000000000000000000001111110000000000000000
            SecondsMask = 0b0000000000000000000000000000000000000000000000001111110000000000
            MillisecondsMask = 0b0000000000000000000000000000000000000000000000000000001111111111

            Year = (self.depthmap.timestamp & YearMask) >> 47
            Month = (self.depthmap.timestamp & MonthMask) >> 43
            Day = (self.depthmap.timestamp & DayMask) >> 38
            Timezone = (self.depthmap.timestamp & TimezoneMask) >> 27
            Hour = (self.depthmap.timestamp & HourMask) >> 22
            Minute = (self.depthmap.timestamp & MinuteMask) >> 16
            Seconds = (self.depthmap.timestamp & SecondsMask) >> 10
            Milliseconds = self.depthmap.timestamp & MillisecondsMask
            return Year, Month, Day, Hour, Minute, Seconds, Milliseconds
