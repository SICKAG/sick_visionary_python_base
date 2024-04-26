import logging
import numpy as np


def convertDistanceToMM(data, xmlParser):
    """
    data:      The distance data that should be converted to millimeters
    xmlParser: XML parser which has parsed the corresponding xml segment
    """

    # Raw output of the devices (before applying exponent)
    #
    # Visionary S (default mode):   Tenth mm
    # Visionary S (65 meter mode):  mm
    # Visionary T:                  mm
    # Visionary T Mini:             quarter mm (not corrected via decimal exponent)

    conversionFactor = 10**xmlParser.decimalExponentDistance
    if xmlParser.tofmini:
        conversionFactor /= 4.0

    logging.info("Converting depth map to millimeters (multiplying with factor {}).".format(
        conversionFactor))
    return np.multiply(data, conversionFactor)
