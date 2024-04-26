# -*- coding: utf-8 -*-
"""
Implementation of binary parser for BLOB data.

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
import struct

from .ParserHelper import DepthMap, Polar2DData, CartesianData, MAX_CONFIDENCE


class BinaryParser:
    """ The binary parser for extracting distance, intensity and confidence from
    the binary segment of the raw data frame.
    """

    def getDepthMap(self,
                    binarySegment,
                    numBytesFrameNumber,
                    numBytesQuality,
                    numBytesStatus,
                    numBytesDistance,
                    numBytesIntensity,
                    numBytesPerIntensityValue,
                    numBytesConfidence):
        position = 0
        # the binary part starts with entries for length, a timestamp
        # and a version identifier
        infoBlockSize = struct.calcsize('<IQH')
        (lengthAtStart, timeStamp, version) = struct.unpack(
            '<IQH', binarySegment[position:position + infoBlockSize])
        position += infoBlockSize
        logging.debug("Length at start: %s", lengthAtStart)
        self.logTimeStamp(timeStamp)
        logging.debug("Format version: %s", version)

        format2BlockSize = 0
        if version == 2:
            assert numBytesFrameNumber == 4
            assert numBytesQuality == 1
            assert numBytesStatus == 1
            format2BlockSize = struct.calcsize('<IBB')
            (frameNumber, quality, status) = struct.unpack(
                '<IBB', binarySegment[position:position + format2BlockSize])
            position += format2BlockSize
            logging.debug("FrameNumber: %s", frameNumber)
            logging.debug("Data quality: %s", quality)
            logging.debug("Device status: %s", status)
        else:
            logging.warning(
                "Old format, no values for frameNumber, quality and status")
            frameNumber = -1
            quality = 0
            status = 0

        dataBlockSize = numBytesDistance + \
            numBytesIntensity + \
            numBytesConfidence  # calculating the end index
        # whole data block
        dataBinary = binarySegment[position:position + dataBlockSize]
        position += dataBlockSize
        # only the distance data (as string)
        distance = dataBinary[0:numBytesDistance]

        logging.debug("Reading distance...")
        distanceData = struct.unpack('<%uH' % (len(distance) / 2), distance)
        logging.debug("...done.")

        # extract the intensity data (same procedure as distance)
        logging.debug("Reading intensity...")
        off = numBytesDistance
        intensity = dataBinary[off:numBytesIntensity + off]
        if numBytesPerIntensityValue == 2:
            intensityData = struct.unpack(
                '<%uH' % (len(intensity) / 2), intensity)
        elif numBytesPerIntensityValue == 4:
            intensityData = struct.unpack(
                '<%uL' % (len(intensity) / 4), intensity)
        else:
            # legacy mode, also used for RGBA -> byte-wise
            intensityData = struct.unpack('<%uB' % len(intensity), intensity)
        logging.debug("...done.")

        # extract the confidence data (same procedure as distance)
        logging.debug("Reading confidence...")
        off += numBytesIntensity
        confidence = dataBinary[off:numBytesConfidence + off]
        confidenceData = struct.unpack(
            '<%uH' % (len(confidence) / 2), confidence)
        logging.debug("...done.")

        # checking if all data is read
        if (position + 4 == lengthAtStart):
            check = struct.calcsize('<II')
            (crc, lengthAtEnd) = struct.unpack(
                '<II', binarySegment[position:position + check])
            position += check
            logging.debug("Length at start: %s", lengthAtStart)
            logging.debug("Length at end: %s", lengthAtEnd)
            # assert lengthAtStart == lengthAtEnd
            if lengthAtStart != lengthAtEnd:
                logging.error("lengthAtStart != lengthAtEnd")
        self.remainingBuffer = binarySegment[position:]

        self.depthmap = DepthMap(
            distanceData, intensityData, confidenceData, frameNumber, quality, status, timeStamp)

    def getPolar2D(self,
                   binarySegment,
                   numPolarValues):
        position = 0
        infoBlockSize = struct.calcsize('<IQHIIffffff')
        if len(binarySegment) < infoBlockSize:
            logging.warning("Found inconsistency in binary polar data.")
            return
        (lengthAtStart, timeStamp, deviceID, scanCounter, syscountScan, scanFrequency, measFrequency, angleFirstScanPoint, angularResolution, scale,
         offset) = struct.unpack('<IQHIIffffff', binarySegment[position:position + infoBlockSize])
        logging.debug("Length = %i" % lengthAtStart)
        position += infoBlockSize

        self.logTimeStamp(timeStamp)
        logging.debug("DeviceID = %i" % deviceID)
        logging.debug("ScanCounter = %i" % scanCounter)
        logging.debug("SyscountScan = %i" % syscountScan)
        logging.debug("ScanFrequency = %i" % scanFrequency)
        logging.debug("MeasFrequency = %i" % measFrequency)
        logging.debug("AngleFirstScanPoint = %i" % angleFirstScanPoint)
        logging.debug("AngularResolution = %i" % angularResolution)
        logging.debug("Scale = %i" % scale)
        logging.debug("Offset = %i" % offset)

        logging.debug("Reading position is now: %i" % position)
        # distanceDataSize = int(singleValueSize * numPolarValues)
        endPosition = position + numPolarValues * struct.calcsize('<f')
        if len(binarySegment) < endPosition:
            logging.warning("Found inconsistency in binary polar data.")
            return
        distanceData = struct.unpack(
            '<%uf' % numPolarValues, binarySegment[position:endPosition])
        logging.debug("Distance data = %s" % str(distanceData))
        position = endPosition
        logging.debug("Reading position is now: %i" % position)

        confidenceBlockSize = struct.calcsize('<ffff')
        endPosition = position + confidenceBlockSize
        if len(binarySegment) < endPosition:
            logging.warning("Found inconsistency in binary polar data.")
            return
        (rssi_startAngle, rssi_angularResolution, rssi_scale, rssi_offset) = struct.unpack(
            '<ffff', binarySegment[position:endPosition])
        logging.debug("RSSI AngleFirstScanPoint = %i" % rssi_startAngle)
        logging.debug("RSSI AngularResolution = %i" % rssi_angularResolution)
        logging.debug("RSSI Scale = %i" % rssi_scale)
        logging.debug("RSSI Offset = %i" % rssi_offset)

        position = endPosition
        logging.debug("Reading position is now: %i" % position)

        endPosition = position + numPolarValues * struct.calcsize('<f')
        if len(binarySegment) < endPosition:
            logging.warning("Found inconsistency in binary polar data.")
            return
        confidenceData = struct.unpack(
            '<%uf' % numPolarValues, binarySegment[position:endPosition])
        logging.debug("Confidence data = %s" % str(confidenceData))
        # convert into percent if needed
        # confidence = tuple((val / MAX_CONFIDENCE) * 100.0 for val in confidenceData)
        position = endPosition
        logging.debug("Reading position is now: %i" % position)

        # checking if all data is read
        if (position + 8 == lengthAtStart):
            check = struct.calcsize('<II')
            endPosition = position + check
            if len(binarySegment) < endPosition:
                logging.warning("Found inconsistency in binary polar data.")
                return
            (crc, lengthAtEnd) = struct.unpack(
                '<II', binarySegment[position:endPosition])
            logging.debug("Length at start: %s", lengthAtStart)
            logging.debug("Length at end: %s", lengthAtEnd)
            assert lengthAtStart == lengthAtEnd
            self.hasRemainingBuffer = False
        else:
            # there is another data set in this binary buffer
            self.hasRemainingBuffer = True
            self.remainingBuffer = binarySegment[position:lengthAtStart + 4]
            self.length = lengthAtStart  # checking if all data is read

        self.polardata = Polar2DData(
            angleFirstScanPoint, angularResolution, distanceData, confidenceData, timeStamp)

    def getCartesian(self,
                     binarySegment):
        position = 0
        infoBlockSize = struct.calcsize('<IQHI')
        if len(binarySegment) < infoBlockSize:
            logging.warning("Found inconsistency in binary polar data.")
            return
        (lengthAtStart, timeStamp, version, numPoints) = struct.unpack(
            '<IQHI', binarySegment[position:position + infoBlockSize])
        logging.debug("Length = %i" % lengthAtStart)
        position += infoBlockSize

        self.logTimeStamp(timeStamp)
        logging.debug("Version = %i" % version)

        logging.debug("Reading position is now: %i" % position)

        endPosition = position + numPoints * \
            struct.calcsize('<ffff')  # 4 float32 values per point
        if len(binarySegment) < endPosition:
            logging.warning("Found inconsistency in binary polar data.")
            return
        pointCloudData = struct.unpack(
            '<%uf' % (numPoints*4), binarySegment[position:endPosition])
        x = pointCloudData[0:numPoints*4:4]
        y = pointCloudData[1:numPoints*4:4]
        z = pointCloudData[2:numPoints*4:4]
        rssi = pointCloudData[3:numPoints*4:4]
        confidence = tuple((val / MAX_CONFIDENCE) * 100.0 for val in rssi)

        position = endPosition
        logging.debug("Reading position is now: %i" % position)
        logging.debug("Point cloud data = %s" % str(pointCloudData))

        # checking if all data is read
        check = struct.calcsize('<II')
        endPosition = position + check
        if len(binarySegment) < endPosition:
            logging.warning("Found inconsistency in binary Cartesian data.")
            return
        (crc, lengthAtEnd) = struct.unpack(
            '<II', binarySegment[position:endPosition])
        logging.debug("Length at start: %s", lengthAtStart)
        logging.debug("Length at end: %s", lengthAtEnd)
        assert lengthAtStart == lengthAtEnd
        self.hasRemainingBuffer = False

        self.cartesianData = CartesianData(
            numPoints, x, y, z, confidence, timeStamp)

    # ===============================================================================

    def logTimeStamp(self, timeStamp):
        # 0x03 D9 08 40 02 C7 B0 00
        # 0000 0011 1101 1001 0000 1000 0100 0000 0000 0010 1100 0111 1011 0000 0000 0000
        # .... .YYY YYYY YYYY YMMM MDDD DDTT TTTT TTTT THHH HHMM MMMM SSSS SSmm mmmm mmmm
        # Bits: 5 unused - 12 Year - 4 Month - 5 Day - 11 Timezone - 5 Hour - 6 Minute - 6 Seconds - 10 Milliseconds
        # .....YYYYYYYYYYYYMMMMDDDDDTTTTTTTTTTTHHHHHMMMMMMSSSSSSmmmmmmmmmm
        YearMask = 0b0000011111111111100000000000000000000000000000000000000000000000
        MonthMask = 0b0000000000000000011110000000000000000000000000000000000000000000
        DayMask = 0b0000000000000000000001111100000000000000000000000000000000000000
        TimezoneMask = 0b0000000000000000000000000011111111111000000000000000000000000000
        HourMask = 0b0000000000000000000000000000000000000111110000000000000000000000
        MinuteMask = 0b0000000000000000000000000000000000000000001111110000000000000000
        SecondsMask = 0b0000000000000000000000000000000000000000000000001111110000000000
        MillisecondsMask = 0b0000000000000000000000000000000000000000000000000000001111111111
        Year = (timeStamp & YearMask) >> 47
        Month = (timeStamp & MonthMask) >> 43
        Day = (timeStamp & DayMask) >> 38
        Timezone = (timeStamp & TimezoneMask) >> 27
        Hour = (timeStamp & HourMask) >> 22
        Minute = (timeStamp & MinuteMask) >> 16
        Seconds = (timeStamp & SecondsMask) >> 10
        Milliseconds = timeStamp & MillisecondsMask
        logging.debug("Data Timestamp [YYYY-MM-DD HH:MM:SS.mm] = %04u-%02u-%02u %02u:%02u:%02u.%03u" % (
            Year, Month, Day, Hour, Minute, Seconds, Milliseconds))
