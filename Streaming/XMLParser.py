# -*- coding: utf-8 -*-
"""
Implementation of XML parser for BLOB header.

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
from xml.etree import cElementTree as ET


class XMLParser:
    """ The XML parser that only extracts the needed information.
        attributes:
            _frameLength: Only set when DepthData is available (otherwise None), otherwise no imageWidth and imageHeight
                         for calculation available.

    """

    def __init__(self):
        self.revision = None
        self.imageWidth = None
        self.imageHeight = None
        self.dataItems = []
        self.cam2worldMatrix = None
        self.fx = None
        self.fy = None
        self.cx = None
        self.cy = None
        self.k1 = None
        self.k2 = None
        self.k3 = None
        self.p1 = None
        self.p2 = None
        self.f2rc = None
        self.availableFrames = None
        self.hasDepthMap = False
        self.hasCartesianData = False
        self.hasPolar2DData = False
        # Decimal exponent for Distance (Visionary T & T Mini) or Z (Visionary S) map
        self.decimalExponentDistance = 0
        # "private"

        self._frameLengthDepthMap = None

    def getFrameLengthDepthMap(self):
        """ Returns the length of the binary depth map segment in bytes. """
        if self._frameLengthDepthMap is not None:
            return self._frameLengthDepthMap
        else:
            logging.error(
                "FrameLength not calculated, since no DepthData is available!")
            return None

    def getDataFormat(self, xmlNode):

        if xmlNode is None:
            raise RuntimeError("ERROR: no xmlNode is not set")

        self.dataItems = []
        # print ET.tostring(xmlNode)
        knownDepthMap = ["TimestampUTC", "Version"]
        knownDataStream = ["FrameNumber", "Quality", "Status",
                           "Z", "Distance", "Intensity", "Confidence"]
        knownSizes = {"uint8": 1, "uint16": 2,
                      "uint32": 4, "uint64": 8, "float32": 4}

        if xmlNode.tag == "DataSetDepthMap" or xmlNode.tag == "DataSetStereo":
            for node in xmlNode.find('FormatDescriptionDepthMap'):
                if node.tag in knownDepthMap:
                    if node.tag == "TimestampUTC":
                        actualSize = "uint64"
                    else:
                        actualSize = node.text
                    logging.debug("Adding data \"{}\" with byte length {}".format(
                        node.tag, knownSizes[actualSize]))
                    self.dataItems.append(
                        {"Name": node.tag, "Size": knownSizes[actualSize]})

            for node in xmlNode.find('FormatDescriptionDepthMap/DataStream'):
                if node.tag in knownDataStream:
                    logging.debug("Adding data \"{}\" with byte length {}".format(
                        node.tag, knownSizes[node.text]))
                    self.dataItems.append(
                        {"Name": node.tag, "Size": knownSizes[node.text]})

        # Equivalent format information for cartesian and polar data of the AG devices is available in the XML nodes with tags
        # DataSetCartesian/FormatDescriptionCartesian and DataSetPolar2D/FormatDescription

    def calcFrameLengthDepthMap(self):
        """Sets self._frameLength to the size of the depth map data in bytes that is send for each frame."""

        if self.imageWidth is None:
            raise RuntimeError(
                "ERROR: imageWidth is not set. Ensure that the device is streaming depth map data.")
        if self.imageHeight is None:
            raise RuntimeError(
                "ERROR: imageHeight is not set. Ensure that the device is streaming depth map data.")

        knownMapNames = ["Z", "Distance", "Intensity", "Confidence"]

        self._frameLengthDepthMap = 0
        for item in self.dataItems:
            if item["Name"] in knownMapNames:
                self._frameLengthDepthMap += item["Size"] * \
                    self.imageWidth * self.imageHeight
            else:
                self._frameLengthDepthMap += item["Size"]

        logging.debug("Calculated framelength (from xml): {} bytes".format(
            self._frameLengthDepthMap))

    def parse(self, xmlString):
        """ Parse method needs the XML segment as string input. """

        sickRecord = ET.fromstring(xmlString)  # the whole block set
        # is called sickrecord
        self.hasDepthMap = False
        self.hasPolar2DData = False
        self.hasCartesianData = False
        # extract camera/image parameters directly from XML
        # =======================================================================

        logging.debug("Parse data items ...")

        # wildcard * should be either DataSetDepthMap or DataSetStereo
        self.getDataFormat(sickRecord.find('DataSets/*'))

        self.stereo = (sickRecord.find('DataSets/DataSetStereo') is not None)
        logging.info(
            " Blob-XML contains DataSets/DataSetStereo ? -> {}".format(self.stereo))

        for dataSetDepthMap in sickRecord.iter('DataSetStereo' if self.stereo else 'DataSetDepthMap'):
            self.availableFrames = int(dataSetDepthMap.get('datacount'))
            logging.debug("datacount: {}".format(self.availableFrames))
            self.binFileName = dataSetDepthMap.find('DataLink/FileName').text
            self.hasDepthMap = True

            self.f2rc = 0.0

            # Recognize if device is a Visionary-T Mini
            for deviceDescription in dataSetDepthMap.iter('DeviceDescription'):
                for ident in deviceDescription.iter('Ident'):
                    self.tofmini = (ident.text.find('Visionary-T Mini') != -1)

            for formatDescriptionDepthMap in dataSetDepthMap.iter('FormatDescriptionDepthMap'):
                for width in formatDescriptionDepthMap.iter('Width'):
                    self.imageWidth = int(width.text)
                for height in formatDescriptionDepthMap.iter('Height'):
                    self.imageHeight = int(height.text)
                for cameraToWorldTransform in formatDescriptionDepthMap.iter('CameraToWorldTransform'):
                    self.cam2worldMatrix = []  # init array
                    for idx, child in enumerate(cameraToWorldTransform):
                        # fill array row by row (4x4 matrix)
                        self.cam2worldMatrix.append(float(child.text))
                # camera intrinsics (fx,fy,cx,cy) are the sixth child in datastream
                for cameraMatrix in formatDescriptionDepthMap.iter('CameraMatrix'):
                    self.fx = float(cameraMatrix.find('FX').text)
                    self.fy = float(cameraMatrix.find('FY').text)
                    self.cx = float(cameraMatrix.find('CX').text)
                    self.cy = float(cameraMatrix.find('CY').text)
                for distortionParams in formatDescriptionDepthMap.iter('CameraDistortionParams'):
                    self.k1 = float(distortionParams.find('K1').text)
                    self.k2 = float(distortionParams.find('K2').text)
                    self.k3 = float(distortionParams.find('K3').text)
                    self.p1 = float(distortionParams.find('P1').text)
                    self.p2 = float(distortionParams.find('P2').text)
                for f2rc in formatDescriptionDepthMap.iter('FocalToRayCross'):
                    self.f2rc = float(f2rc.text)
                for frameNumber in formatDescriptionDepthMap.iter('FrameNumber'):
                    if frameNumber.text.lower() == 'uint32':
                        self.numBytesFrameNumber = 4
                for quality in formatDescriptionDepthMap.iter('Quality'):
                    if quality.text.lower() == 'uint8':
                        self.numBytesQuality = 1
                for status in formatDescriptionDepthMap.iter('Status'):
                    if status.text.lower() == 'uint8':
                        self.numBytesStatus = 1
                if self.stereo:
                    for Z in formatDescriptionDepthMap.iter('Z'):
                        self.distType = Z.text
                        self.decimalExponentDistance = int(
                            Z.attrib['decimalexponent'])
                        if Z.text.lower() == 'uint16':
                            self.numBytesPerZValue = 2
                            self.numBytesPerDistanceValue = 2  # legacy for ssr-loader
                else:
                    for distance in formatDescriptionDepthMap.iter('Distance'):
                        self.distType = distance.text
                        self.decimalExponentDistance = int(
                            distance.attrib['decimalexponent'])
                        if distance.text.lower() == 'uint16':
                            self.numBytesPerDistanceValue = 2
                for intensity in formatDescriptionDepthMap.iter('Intensity'):
                    self.intsType = intensity.text
                    if intensity.text.lower() == 'uint16':
                        self.numBytesPerIntensityValue = 2
                    elif intensity.text.lower() == 'uint32':
                        self.numBytesPerIntensityValue = 4
                for confidence in formatDescriptionDepthMap.iter('Confidence'):
                    self.confType = confidence.text
                    if confidence.text.lower() == 'uint16':
                        self.numBytesPerConfidenceValue = 2

            self.calcFrameLengthDepthMap()
        # =======================================================================
        for dataSetPolar2D in sickRecord.iter('DataSetPolar2D'):
            self.hasPolar2DData = True
            for formatDescription in dataSetPolar2D.iter('FormatDescription'):
                for dataStream in formatDescription.iter('DataStream'):
                    if dataStream.attrib.get('type') == 'distance':
                        self.numPolarValues = int(
                            dataStream.attrib.get('datalength'))
        # =======================================================================
        for dataSetCartesian in sickRecord.iter('DataSetCartesian'):
            self.hasCartesianData = True
            for formatDescriptionCartesian in dataSetCartesian.iter('FormatDescriptionCartesian'):
                for dataStream in formatDescriptionCartesian.iter('DataStream'):
                    for length in dataStream.iter('Length'):
                        assert (length.text.lower() == 'uint32')
                    for x in dataStream.iter('X'):
                        assert (x.text.lower() == 'float32')
                    for y in dataStream.iter('Y'):
                        assert (y.text.lower() == 'float32')
                    for z in dataStream.iter('Z'):
                        assert (z.text.lower() == 'float32')
                    # 'Intensity is not a typo, we abuse this element in the format for confidence values
                    for confidence in dataStream.iter('Intensity'):
                        assert (confidence.text.lower() == 'float32')

        # needed to support BLOBs without confidence (e.g. for Visionary-T VGA)
        if not hasattr(self, 'numBytesPerConfidenceValue'):
            logging.info('force numBytesPerConfidenceValue to 0')
            self.numBytesPerConfidenceValue = 0
