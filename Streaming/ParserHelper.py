# -*- coding: utf-8 -*-
"""
Implementation of parser data structures.

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


class DepthMap:
    """ This class contains the depth map data """

    def __init__(self, distance, intensity, confidence, frameNumber, dataQuality, deviceStatus, timestamp):
        self.distance = distance
        self.intensity = intensity
        self.confidence = confidence
        self.frameNumber = frameNumber
        self.dataQuality = dataQuality
        self.deviceStatus = deviceStatus
        self.timestamp = timestamp


class Polar2DData:
    """ This class contains the polar 2D data """

    def __init__(self, angleFirstScanPoint, angularResolution, distance, confidence, timestamp):
        self.distance = distance
        self.angleFirstScanPoint = angleFirstScanPoint
        self.angularResolution = angularResolution
        self.confidence = confidence
        self.timestamp = timestamp


class CartesianData():
    """ This class contains the polar 2D data """

    def __init__(self, numPoints, x, y, z, confidence, timestamp):
        self.numPoints = numPoints
        self.x = x
        self.y = y
        self.z = z
        self.confidence = confidence
        self.timestamp = timestamp


class CameraParameters:
    """ This class gathers the main camera parameters. """

    def __init__(self, width=176, height=144,
                 cam2worldMatrix=None,
                 fx=146.5, fy=146.5, cx=84.4, cy=71.2,
                 k1=0.326442, k2=0.219623, k3=0, p1=0, p2=0,
                 f2rc=0.0):
        self.cam2worldMatrix = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]

        self.width = width
        self.height = height
        if cam2worldMatrix:
            self.cam2worldMatrix = cam2worldMatrix
        self.fx = fx
        self.fy = fy
        self.cx = cx
        self.cy = cy
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.p1 = p1
        self.p2 = p2
        self.f2rc = f2rc


MAX_CONFIDENCE = 65535
