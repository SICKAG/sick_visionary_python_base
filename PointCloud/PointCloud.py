# -*- coding: utf-8 -*-
"""
This function converts depth data to world coordinates

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

import math
import numpy as np

plyHeader = """ply
format ascii 1.0
comment Exported by visionary python samples
element vertex {}
property float32 x
property float32 y
property float32 z
property uint8 r
property uint8 g
property uint8 b
property float32 i
end_header
"""


def convertToPointCloud(distData, intsData, cnfiData, myCamParams, isStereo):
    """
    Return values:
    wCoordinates: Nested List with the linewise data for a pointcloud file. Each list item is a list with the following entries 
                  X Y Z R G B I   i.e. point coordinates (XYZ), color (RGB) and intensity (I)
    distData: input distData reshaped to array with camera resolution
    """
    wCoordinates = []

    m_c2w = np.array(myCamParams.cam2worldMatrix)
    shape = (4, 4)
    m_c2w.shape = shape

    cnfiData = np.asarray(cnfiData).reshape(
        myCamParams.height, myCamParams.width)
    intsData = np.asarray(intsData).reshape(
        myCamParams.height, myCamParams.width)
    distData = np.asarray(list(distData)).reshape(
        myCamParams.height, myCamParams.width)

    if isStereo:

        # RGBA intensities
        intsData = np.asarray(intsData).astype('uint32').view(
            'uint8').reshape(myCamParams.height, myCamParams.width, 4)
        intsData = np.frombuffer(intsData, np.uint8).reshape(
            myCamParams.height, myCamParams.width, 4)
        color_map = intsData

        # Apply the Statemap to the Z-map
        zmapData_with_statemap = np.array(distData).reshape(
            myCamParams.height, myCamParams.width)

        for row in range(myCamParams.height):
            for col in range(myCamParams.width):
                if (cnfiData[row][col] != 0):
                    # Set invalid pixels to lowest value
                    zmapData_with_statemap[row][col] = 0
                else:
                    # use all "good" points to export to PLY

                    # transform into camera coordinates (zc, xc, yc)
                    xp = (myCamParams.cx - col) / myCamParams.fx
                    yp = (myCamParams.cy - row) / myCamParams.fy

                    # coordinate system local to the imager
                    zc = distData[row][col]
                    xc = xp * zc
                    yc = yp * zc

                    # convert to world coordinate system
                    xw = (m_c2w[0, 3] + zc * m_c2w[0, 2] +
                          yc * m_c2w[0, 1] + xc * m_c2w[0, 0])
                    yw = (m_c2w[1, 3] + zc * m_c2w[1, 2] +
                          yc * m_c2w[1, 1] + xc * m_c2w[1, 0])
                    zw = (m_c2w[2, 3] + zc * m_c2w[2, 2] +
                          yc * m_c2w[2, 1] + xc * m_c2w[2, 0])

                    # merge 3D coordinates and color
                    wCoordinates.append(
                        [xw, yw, zw, color_map[row][col][0], color_map[row][col][1], color_map[row][col][2], 0])

        return wCoordinates, distData

    else:

        for row in range(0, myCamParams.height):
            for col in range(0, myCamParams.width):

                # calculate radial distortion
                xp = (myCamParams.cx - col) / myCamParams.fx
                yp = (myCamParams.cy - row) / myCamParams.fy

                r2 = (xp * xp + yp * yp)
                r4 = r2 * r2

                k = 1 + myCamParams.k1 * r2 + myCamParams.k2 * r4

                xd = xp * k
                yd = yp * k

                d = distData[row][col]
                s0 = np.sqrt(xd*xd + yd*yd + 1)

                xc = xd * d / s0
                yc = yd * d / s0
                zc = d / s0 - myCamParams.f2rc

                # convert to world coordinate system
                xw = (m_c2w[0, 3] + zc * m_c2w[0, 2] +
                      yc * m_c2w[0, 1] + xc * m_c2w[0, 0])
                yw = (m_c2w[1, 3] + zc * m_c2w[1, 2] +
                      yc * m_c2w[1, 1] + xc * m_c2w[1, 0])
                zw = (m_c2w[2, 3] + zc * m_c2w[2, 2] +
                      yc * m_c2w[2, 1] + xc * m_c2w[2, 0])

                # convert to full decibel values * 0.01, which is the same format that Sopas uses for point cloud export
                intsSopasFormat = round(
                    0.2 * math.log10(intsData[row][col]), 2) if intsData[row][col] > 0 else 0

                # merge 3D coordinates and intensity
                wCoordinates.append([xw, yw, zw, 0, 0, 0, intsSopasFormat])

        return wCoordinates, distData


def convertToPointCloudOptimized(distData: list, cnfiData: list, myCamParams: list, isStereo: bool):
    """
    This function converts 2D image data to a 3D point cloud.

    Parameters:
    distData (list): The distance data from the sensor, as a list.
    cnfiData (list): The confidence data from the sensor, as a list.
    myCamParams (list): The camera parameters, as a list.
    isStereo (bool): A flag indicating whether the camera is a stereo camera.

    Returns:
    wCoordinates (numpy.ndarray): A 3D numpy array of shape (camera height, camera width, 3). Each triplet at position [y,x,:] represents the 3D coordinates (in millimeters) of the point at (y_pixel,x_pixel) in the image. So, x_mms, y_mms, z_mms.

    Usage:
    To use the returned point cloud, you can do the following:

    cloud = convertToPointCloud(distData, cnfiData, myCamParams, isStereo)
    x_MMS, y_MMS, z_MMS = cloud[y_pixel, x_pixel, :]

    Note:
    This function overwrites the camera mounting setting parameters from SOPAS. These will always be ignored.
    """

    wCoordinates = []

    # the distance from the sensor to the origin of the camera coordinate system in z
    SENSOR_TO_ORIGIN_DIST = myCamParams.cam2worldMatrix[11]

    # the orientation matrix of the camera, ignoring all sopas/previous configurations!!!!!!!!!!!!!!!!
    m_c2w = np.array([
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, SENSOR_TO_ORIGIN_DIST],
        [0, 0, 0, 1]
    ])

    shape = (4, 4)
    m_c2w.shape = shape
    distData = np.asarray(list(distData)).reshape(
        myCamParams.height, myCamParams.width)
    cnfiData = np.asarray(cnfiData).reshape(
        myCamParams.height, myCamParams.width)

    if isStereo:
        # return wCoordinates
        cols = np.arange(0, myCamParams.width)
        rows = np.arange(0, myCamParams.height)
        xp = (cols - myCamParams.cx) / myCamParams.fx
        yp = (rows - myCamParams.cy) / myCamParams.fy
        xp = xp[:, np.newaxis]
        yp = yp[np.newaxis, :]

        xc = distData * xp.T
        yc = yp.T * distData

        zc = distData

        xw = (m_c2w[0, 3] + zc * m_c2w[0, 2] +
              yc * m_c2w[0, 1] + xc * m_c2w[0, 0])
        yw = (m_c2w[1, 3] + zc * m_c2w[1, 2] +
              yc * m_c2w[1, 1] + xc * m_c2w[1, 0])
        zw = (m_c2w[2, 3] + zc * m_c2w[2, 2] +
              yc * m_c2w[2, 1] + xc * m_c2w[2, 0])

        wCoordinates = np.stack([xw, yw, zw], axis=-1)
        cloud_data_like_sopas = wCoordinates.reshape(
            (myCamParams.height, myCamParams.width, 3))
        '''
        offset the entire cordinate system so that the middle pixel is at (0,0,z) ->
        i want to define the system so that the technical drawing, point 7 in here: https://www.sick.com/il/en/catalog/products/machine-vision-and-identification/machine-vision/visionary-t-mini/v3s105-1aaaaaa/p/p665983?tab=detail
        is at (0,0,z) in the world cordinate system.
        that point is defined in pixel coordinates as: (myCamParams.width // 2, myCamParams.height // 2). 
        so range_data[myCamParams.height // 2, myCamParams.width // 2] is the distance from sensor of that point.
        and cloud_data[myCamParams.height // 2, myCamParams.width // 2,:] is the 3D coordinates of that point.
        '''
        cloud_data = cloud_data_like_sopas.copy()
        sensor_center_x_y_values = (cloud_data_like_sopas[myCamParams.height // 2, myCamParams.width //
                                    2, :2] + cloud_data_like_sopas[(-1+myCamParams.height) // 2, (-1+myCamParams.width) // 2, :2])/2
        # making the middle pixel be the origin of the coordinates system (x=0,y=0) and each point is relative to it
        cloud_data[:, :, :2] = cloud_data_like_sopas[:, :, :2] - \
            sensor_center_x_y_values
        # where cnfiData is 0, so set it to a numpy array of 0,0,0
        cloud_data[cnfiData != 0] = np.array([0, 0, 0])

        return cloud_data

    else:
        # Calculate radial distortion
        cols = np.arange(0, myCamParams.width)
        rows = np.arange(0, myCamParams.height)
        xp = (cols - myCamParams.cx) / myCamParams.fx
        yp = (rows - myCamParams.cy) / myCamParams.fy
        r2 = (xp[:, np.newaxis] ** 2) + (yp[np.newaxis, :] ** 2)
        r4 = r2 ** 2
        k = 1 + myCamParams.k1 * r2 + myCamParams.k2 * r4

        # Correct the shape of xp, yp for broadcasting
        xp = xp[:, np.newaxis]
        yp = yp[np.newaxis, :]

        # Calculate the distortion matrix
        distortion_matrix = np.array([xp * k, yp * k])

        # Convert to 3D coordinates
        s0 = np.sqrt(distortion_matrix[0] ** 2 + distortion_matrix[1] ** 2 + 1)
        xc = distortion_matrix[0].T * distData / s0.T
        yc = distortion_matrix[1].T * distData / s0.T
        zc = distData / s0.T - myCamParams.f2rc

        # Convert to world coordinate system
        coords = m_c2w @ np.vstack([xc.flatten(), yc.flatten(),
                                   zc.flatten(), np.ones_like(xc.flatten())])

        # Reshape back to original shape
        coords = coords.reshape((4, -1))

        # Merge 3D coordinates and intensity
        wCoordinates = np.column_stack([coords[0], coords[1], coords[2]])
        cloud_data_like_sopas = wCoordinates.reshape(
            (myCamParams.height, myCamParams.width, 3))

        '''
        offset the entire cordinate system so that the middle pixel is at (0,0,z) ->
        i want to define the system so that the technical drawing, point 7 in here:
        https://www.sick.com/il/en/catalog/products/machine-vision-and-identification/machine-vision/visionary-t-mini/v3s105-1aaaaaa/p/p665983?tab=detail
        is at (0,0,z) in the world cordinate system.
        that point is defined in pixel coordinates as: (myCamParams.width // 2, myCamParams.height // 2). 
        so range_data[myCamParams.height // 2, myCamParams.width // 2] is the distance from sensor of that point.
        and cloud_data[myCamParams.height // 2, myCamParams.width // 2,:] is the 3D coordinates of that point.
        '''
        cloud_data = cloud_data_like_sopas.copy()
        sensor_center_x_y_values = (cloud_data_like_sopas[myCamParams.height // 2, myCamParams.width //
                                    2, :2] + cloud_data_like_sopas[(-1+myCamParams.height) // 2, (-1+myCamParams.width) // 2, :2])/2
        # making the middle pixel be the origin of the coordinates system (x=0,y=0) and each point is relative to it
        cloud_data[:, :, :2] = cloud_data_like_sopas[:, :, :2] - \
            sensor_center_x_y_values

        # where cnfiData is 0, so set it to a numpy array of 0,0,0
        cloud_data[cnfiData != 0] = np.array([0, 0, 0])

        return cloud_data


def writePointCloudToPLY(filename, wCoordinates):
    with open(filename, 'w') as f:
        f.write(plyHeader.format(len(wCoordinates)))
        for item in wCoordinates:
            for l in item:
                f.write(("{} ").format(l))
            f.write("\n")


def writePointCloudToPCD(filename, wCoordinates):
    with open(filename, 'w') as f:
        f.write("# .PCD v.7 - Point Cloud Data file format\n")
        f.write("VERSION .7\n")
        f.write("FIELDS x y z\n")
        f.write("SIZE 4 4 4\n")
        f.write("TYPE F F F\n")
        f.write("COUNT 1 1 1\n")
        f.write("WIDTH {}\n".format(len(wCoordinates)))
        f.write("HEIGHT 1\n")
        f.write("VIEWPOINT 0 0 0 1 0 0 0\n")
        f.write("POINTS {}\n".format(len(wCoordinates)))
        f.write("DATA ascii\n")
        for item in wCoordinates:
            f.write(("{} {} {}\n").format(item[0], item[1], item[2]))
