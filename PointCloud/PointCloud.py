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
from functools import lru_cache
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


@lru_cache(maxsize=32)
def _get_normalized_pixel_coordinates(width: int, height: int, cx: float, cy: float, fx: float, fy: float):
    """Return cached normalized pixel coordinate vectors for a camera setup."""
    cols = np.arange(0, width)
    rows = np.arange(0, height)
    xp = (cols - cx) / fx
    yp = (rows - cy) / fy
    # Keep cached arrays immutable to avoid accidental cross-call mutation.
    xp.setflags(write=False)
    yp.setflags(write=False)
    return xp, yp


def getNormalizedPixelCoordinates(myCamParams):
    """Get normalized pixel coordinates (xp, yp) from cache for the given camera parameters."""
    return _get_normalized_pixel_coordinates(
        int(myCamParams.width),
        int(myCamParams.height),
        float(myCamParams.cx),
        float(myCamParams.cy),
        float(myCamParams.fx),
        float(myCamParams.fy),
    )


@lru_cache(maxsize=32)
def _get_mono_distortion_grids(width: int, height: int, cx: float, cy: float, fx: float, fy: float, k1: float, k2: float):
    """Return cached radial distortion grids (r2, r4, k) for mono camera."""
    xp, yp = _get_normalized_pixel_coordinates(width, height, cx, cy, fx, fy)

    # Broadcast pixel coordinates to 2D grids and compute distortion factors
    r2 = (xp[:, np.newaxis] ** 2) + (yp[np.newaxis, :] ** 2)
    r4 = r2 ** 2
    k = 1 + k1 * r2 + k2 * r4

    # Make immutable to prevent accidental mutation of cached data
    r2.setflags(write=False)
    r4.setflags(write=False)
    k.setflags(write=False)

    return r2, r4, k


def getMonoDistortionGrids(myCamParams):
    """Get cached radial distortion grids (r2, r4, k) for the given camera parameters."""
    return _get_mono_distortion_grids(
        int(myCamParams.width),
        int(myCamParams.height),
        float(myCamParams.cx),
        float(myCamParams.cy),
        float(myCamParams.fx),
        float(myCamParams.fy),
        float(myCamParams.k1),
        float(myCamParams.k2),
    )


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

    # Fetch cached normalized pixel coordinates for this camera setup.
    xp, yp = getNormalizedPixelCoordinates(myCamParams)

    if isStereo:
        # return wCoordinates
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
        # Fetch cached radial distortion grids for this camera setup
        r2, r4, k = getMonoDistortionGrids(myCamParams)

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


def writePointCloudToPLY(filename, wCoordinates, binary=False):
    points = np.asarray(wCoordinates)
    if points.ndim == 1:
        points = points.reshape(-1, 3)
    elif points.ndim > 2:
        points = points.reshape(-1, points.shape[-1])

    if points.shape[1] < 3:
        raise ValueError(
            "wCoordinates must contain at least 3 columns for x, y, z")

    has_color_intensity = points.shape[1] >= 7
    num_points = points.shape[0]

    if binary:
        if has_color_intensity:
            header = (
                "ply\n"
                "format binary_little_endian 1.0\n"
                "comment Exported by visionary python samples\n"
                f"element vertex {num_points}\n"
                "property float x\n"
                "property float y\n"
                "property float z\n"
                "property uchar red\n"
                "property uchar green\n"
                "property uchar blue\n"
                "property float intensity\n"
                "end_header\n"
            )
            out = np.empty(num_points, dtype=[('x', '<f4'), ('y', '<f4'), ('z', '<f4'),
                                              ('r', 'u1'), ('g', 'u1'), ('b', 'u1'), ('i', '<f4')])
            out['x'] = points[:, 0].astype(np.float32, copy=False)
            out['y'] = points[:, 1].astype(np.float32, copy=False)
            out['z'] = points[:, 2].astype(np.float32, copy=False)
            out['r'] = points[:, 3].astype(np.uint8, copy=False)
            out['g'] = points[:, 4].astype(np.uint8, copy=False)
            out['b'] = points[:, 5].astype(np.uint8, copy=False)
            out['i'] = points[:, 6].astype(np.float32, copy=False)
        else:
            header = (
                "ply\n"
                "format binary_little_endian 1.0\n"
                "comment Exported by visionary python samples\n"
                f"element vertex {num_points}\n"
                "property float x\n"
                "property float y\n"
                "property float z\n"
                "end_header\n"
            )
            out = np.empty(num_points, dtype=[
                           ('x', '<f4'), ('y', '<f4'), ('z', '<f4')])
            out['x'] = points[:, 0].astype(np.float32, copy=False)
            out['y'] = points[:, 1].astype(np.float32, copy=False)
            out['z'] = points[:, 2].astype(np.float32, copy=False)

        with open(filename, 'wb', buffering=1024 * 1024) as f:
            f.write(header.encode('ascii'))
            f.write(out.tobytes(order='C'))
    else:
        if has_color_intensity:
            header = plyHeader.format(num_points)
            ascii_data = points[:, :7]
            fmt = '%.6f %.6f %.6f %d %d %d %.6f'
        else:
            header = (
                "ply\n"
                "format ascii 1.0\n"
                "comment Exported by visionary python samples\n"
                f"element vertex {num_points}\n"
                "property float32 x\n"
                "property float32 y\n"
                "property float32 z\n"
                "end_header\n"
            )
            ascii_data = points[:, :3]
            fmt = '%.6f %.6f %.6f'

        with open(filename, 'w', buffering=1024 * 1024) as f:
            f.write(header)
            np.savetxt(f, ascii_data, fmt=fmt)


def writePointCloudToPCD(filename, wCoordinates, binary=False):
    points = np.asarray(wCoordinates)
    if points.ndim == 1:
        points = points.reshape(-1, 3)
    elif points.ndim > 2:
        points = points.reshape(-1, points.shape[-1])

    if points.shape[1] < 3:
        raise ValueError(
            "wCoordinates must contain at least 3 columns for x, y, z")

    xyz = points[:, :3]
    num_points = xyz.shape[0]

    data_mode = "binary" if binary else "ascii"
    header = (
        "# .PCD v.7 - Point Cloud Data file format\n"
        "VERSION .7\n"
        "FIELDS x y z\n"
        "SIZE 4 4 4\n"
        "TYPE F F F\n"
        "COUNT 1 1 1\n"
        f"WIDTH {num_points}\n"
        "HEIGHT 1\n"
        "VIEWPOINT 0 0 0 1 0 0 0\n"
        f"POINTS {num_points}\n"
        f"DATA {data_mode}\n"
    )

    if binary:
        xyz32 = np.ascontiguousarray(xyz, dtype=np.float32)
        with open(filename, 'wb', buffering=1024 * 1024) as f:
            f.write(header.encode('ascii'))
            f.write(xyz32.tobytes(order='C'))
    else:
        with open(filename, 'w', buffering=1024 * 1024) as f:
            f.write(header)
            if isinstance(xyz, np.ndarray):
                np.savetxt(f, xyz, fmt='%.6f %.6f %.6f')
            else:
                f.writelines(
                    f"{item[0]:.6f} {item[1]:.6f} {item[2]:.6f}\n" for item in xyz)
