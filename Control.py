# -*- coding: utf-8 -*-
"""
This module handles the device connection. It allows to connect
to a Visionary device. The device is connected via two channels -
one for the control commands and one for streaming.

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

import binascii
import hashlib
import logging
import socket
import struct
import time
from typing import List, Tuple

from .Protocol.Cola2 import Cola2
from .Protocol.ColaB import ColaB

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------------------------------------------------

# device settings
TCP_PORT_BLOBSERVER = 2114  # standard port for data stream
# You have to use SOPAS ET in order to change these settings for the device

# constants
# START_STX = b'\x02\x02\x02\x02'  # start sequence of the CoLa protocol
PAYLOAD_OFFSET = 8  # payload starts after an offset of 8 bytes
FRAGMENT_SIZE = 1024  # tcp fragment size of the data stream
# USERLEVEL_OPERATOR = 1
# USERLEVEL_MAINTENANCE = 2
# USERLEVEL_AUTH_CLIENT = 3
# USERLEVEL_SERVICE = 4

TRANSPORTPROTOCOLAPI_TCP = 0
TRANSPORTPROTOCOLAPI_UDP = 1

ACQUISITIONMODE_NORMAL = 0
ACQUISITIONMODE_HDR = 1
ACQUISITIONMODE_HIGHSPEED = 2

ACQUISITIONMODESTEREO_NORMAL = 0
ACQUISITIONMODESTEREO_HDR = 1
ACQUISITIONMODESTEREO_HQM = 2

FRONTENDMODE_CONTINUOUS = 0
FRONTENDMODE_STOP = 1
FRONTENDMODE_EXTERNALTRIGGER = 2

# Device is in a stand-by mode, that keeps streaming data albeit without usable data
POWERMODE_STREAMING_STANDBY = 5
POWERMODE_ACTIVE = 6  # Device is up and running

# The depth range is limited to 0.5 ... 6.5m and provides sub mm precision.
DISTANCEMODE_SHORT_RANGE = 0
# The working range is increased to 0.5m ... 65m and provides mm precision.
DISTANCEMODE_LONG_RANGE = 0

# miscellaneous
MESSAGE_STATE_ACTIVE = 1
STRUCT_FLEX16 = struct.Struct('>H')


def to_ascii(str_value):
    """ just to produce a readable output of the device responses """
    return binascii.b2a_qp(str_value)


def to_hex(str_value):
    """ just to produce a readable output of the device responses """
    return ' '.join(x.encode('hex') for x in str_value)


class SrtLogin(object):
    def __init__(self, control, userlevel, password):
        """
        Create a new CoLa login/logout context manager.

        :param Device.Control control: CoLa control channel object
        :param int userlevel: userlevel enum value
        :param int password: password hash
        """
        self.__control = control
        self.__userlevel = userlevel
        self.__password = password

    def __enter__(self):
        """
        :return: CoLa control channel object
        :rtype: Device.Control
        """
        self.__control.login(self.__userlevel, self.__password)
        return self.__control

    def __exit__(self, exc_type, exc_value, traceback):
        self.__control.logout()
        return False


class Control:
    """ all methods that use the control channel (sopas) """

    USERLEVEL_OPERATOR = 1
    USERLEVEL_MAINTENANCE = 2
    USERLEVEL_AUTH_CLIENT = 3
    USERLEVEL_SERVICE = 4

    USER_LEVEL_NAMES = [
        "Run",              # 0
        "Operator",         # 1
        "Maintenance",      # 2
        "AuthorizedClient",  # 3
        "Service"           # 4
    ]

    SULVERSION_UNKNOWN = -1
    SULVERSION_1 = 1
    SULVERSION_2 = 2

    def __init__(self, ipAddress, protocol, control_port=None, timeout=5, sulVersion=SULVERSION_UNKNOWN):
        self.ipAddress = ipAddress
        self.timeout = timeout
        self.sessionId = -1
        self.reqId = 0
        self.control_port = control_port
        self.sulVersion = sulVersion
        # must be divided to take into account place for base64 encoding
        # DevTool supports 32768, for compatibility stay with 16k
        self.maxFileBufferLength = int(16384 / 1.334)

        if protocol == ColaB.PROTOCOL_Name_STR:
            self.protocol = ColaB()
        elif protocol == Cola2.PROTOCOL_Name_STR:
            self.protocol = Cola2()
        else:
            raise Exception(
                "invalid argument: supported protocols ColaB, Cola2")

        if (control_port != None):
            self.control_port = control_port
        else:
            self.control_port = self.protocol.DEFAULT_PORT

        logger.info("Control() ip: {}, port: {}, protocol: {}".format(
            self.ipAddress, str(self.control_port), self.protocol))

    def open(self):
        """ establish the control channel to the device """
        logger.info("Connecting to device...")
        self.sock_sopas = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_sopas.settimeout(self.timeout)

        try:
            self.sock_sopas.connect((self.ipAddress, self.control_port))
        except:
            logging.error("Failed to connect to device at {}:{}".format(
                self.ipAddress, self.control_port))
            raise

        logger.info("done.")

    def close(self):
        """ close device control channel """
        if self.sock_sopas is not None:
            logging.info("Closing device connection...")
            self.sock_sopas.close()
            logging.info("done.")

    def calculateChallengeHash(self, strUser, strPassword, challenge, salt=None):
        password = (strUser + ':SICK Sensor:' +
                    strPassword).encode('utf-8')

        if salt is not None:
            password = password + ':'.encode('utf-8') + bytearray(salt)

        sha256 = hashlib.sha256()
        sha256.update(password)
        pw_hash = sha256.digest()

        # calculate challenge response
        sha256 = hashlib.sha256()
        sha256.update(pw_hash + bytearray(challenge))
        challenge_response = sha256.digest()

        return list(bytearray(challenge_response))

    def calculatePasswordHash(self, strPassword):
        m = hashlib.md5()  # use new hashlib
        m.update(strPassword.encode('utf8'))
        dig = m.digest()
        dig = [x for x in bytearray(dig)]  # convert bytes to int
        # 128 bit to 32 bit by XOR
        byte0 = dig[0] ^ dig[4] ^ dig[8] ^ dig[12]
        byte1 = dig[1] ^ dig[5] ^ dig[9] ^ dig[13]
        byte2 = dig[2] ^ dig[6] ^ dig[10] ^ dig[14]
        byte3 = dig[3] ^ dig[7] ^ dig[11] ^ dig[15]
        retValue = byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24)
        return retValue

    def pack_flexstring(self, s):
        """ packs and return a cola flexstring (with 16bit length) for a given string """
        if not isinstance(s, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        return STRUCT_FLEX16.pack(len(s)) + s

    def unpack_flexstring_from(self, buf, offset=0):
        """ unpacks a cola flexstring (with 16bit length) and returns the string and the length taken"""
        if not isinstance(buf, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        length, = STRUCT_FLEX16.unpack_from(buf, offset)
        start = offset + STRUCT_FLEX16.size
        end = start + length
        s = buf[start:end]
        return s, end

    def unpack_flexstring_from_cola_a(self, buf, offset=0):
        if not isinstance(buf, bytes):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        end = buf[offset:].find(' ')
        if end < 0:
            raise RuntimeError('Cannot identify string length correctly')
        strlen = int(buf[offset:offset + end])  # use unpack instead of int ?
        offset += (end + 1)  # +1 for separating space char
        s = buf[offset:offset + strlen]
        offset += (strlen + 1)  # +1 for separating space char
        return s, offset

    def sendCommand(self, cmd, name, payload=None):
        if not payload:
            payload = bytes()

        if (not isinstance(cmd, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        if (not isinstance(name, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")
        if (not isinstance(payload, bytes)):
            raise RuntimeError("invalid protocol string (not a bytes object)")

        payload = name + b' ' + payload

        recvCmd, recvMode, payload = self.protocol.send(
            self.sock_sopas, cmd, b'N', payload)

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
                error_code, = struct.unpack_from('>H', payload)
                self.protocol.raise_cola_error(error_code)
            else:
                raise RuntimeError(
                    "unexpected response packet, expected command {!r}; got {!r}".format(expectedCmd, recvCmd))

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

    def reboot(self):
        """ reboot device """
        logger.info("Rebooting device...")
        self.sendCommand(b'M', b'mSCreboot')
        logger.info("done.")

    def readVariable(self, name):
        """ returns data from a variable """
        if (not isinstance(name, bytes)):
            raise RuntimeError("invalid protocol string (!bytes)")
        return self.sendCommand(b'R', name)

    def writeVariable(self, name, data=None):
        """ write data to a variable """
        self.sendCommand(b'W', name, data)

    def invokeMethod(self, name, data=b''):
        """ Invoke method. """
        if (not isinstance(name, bytes)):
            raise RuntimeError("invalid protocol string (!bytes)")
        if (not isinstance(data, bytes)):
            raise RuntimeError("invalid protocol string (!bytes)")

        logger.info("Invoking %s method..." % name)
        rx = self.sendCommand(b'M', name, data)
        logger.info("... done.")
        return rx

    def initStream(self):
        """ Tells the device that there is a streaming channel by invoking a
        method named GetBlobClientConfig.
        """
        self.invokeMethod(b'GetBlobClientConfig')

    def startStream(self):
        """ Start streaming the data by calling the "PLAYSTART" method on the
        device and sending a "Blob request" afterwards.
        """
        self.invokeMethod(b'PLAYSTART')

    def stopStream(self):
        """ Stops the data stream. """
        self.invokeMethod(b'PLAYSTOP')

    def singleStep(self):
        """ Triggers one image. """
        self.invokeMethod(b'PLAYNEXT')

    ''' Activate polar 2D data reduction '''

    def activatePolar2DReduction(self):
        self.writeVariable(b'enPolar', struct.pack('B', 1))

    ''' Deactivate polar 2D data reduction '''

    def deactivatePolar2DReduction(self):
        self.writeVariable(b'enPolar', struct.pack('B', 0))

    ''' Activate Cartesian data reduction '''

    def activateCartesianReduction(self):
        self.writeVariable(b'enCart', struct.pack('B', 1))

    ''' Deactivate Cartesian data reduction '''

    def deactivateCartesianReduction(self):
        self.writeVariable(b'enCart', struct.pack('B', 0))

    # Wait until device reached READY state
    def waitForReady(self):
        STATE_READY = 1
        # In EDP the default timeout is 1s (see RunLevelManager implementation)
        # This means the device need to return to a stable READY state within 1s
        # To be sure this function waits double that time (2s)
        tStart = time.time()
        while (tStart + 2) > time.time():
            rx = self.readVariable("deviceState")
            deviceState = struct.unpack('>H', rx)[0]
            if deviceState == STATE_READY:
                return
            time.sleep(0.005)  # avoid DoS on SOPAS Cmd handling
        raise RuntimeError(
            "Device did not reached READY state after 2 seconds")

    def waitForReductionParamsApplied(self, timeout_s=5):
        """Waits until applyingParams is false or until the timeout (seconds) is reached.
        Note that a frame needs to be triggered that cartesian or polar reduction are applied when in single step mode.
        :return: false if timeout was reached, otherwise true"""
        counter = 0
        while counter < timeout_s:
            time.sleep(1)
            counter = counter + 1
            rx = self.readVariable(b'applyingParams')
            if int(rx[-1]) != 1:  # use unpack instead of int ?
                return True
        logger.info("Timeout reached while waiting for params!")
        return False

    ''' Enable depth map data channel '''

    def enableDepthMapDataTransfer(self):
        self.writeVariable(b'enDepthAPI', struct.pack('B', 1))

    ''' Disables depth map data channel. '''

    def disableDepthMapDataTransfer(self):
        self.writeVariable(b'enDepthAPI', struct.pack('B', 0))

    ''' Enable polar 2D data channel '''

    def enablePolar2DDataTransfer(self):
        self.writeVariable(b'enPolarAPI', struct.pack('B', 1))

    ''' Disables polar 2D data channel. '''

    def disablePolar2DDataTransfer(self):
        self.writeVariable(b'enPolarAPI', struct.pack('B', 0))

    ''' Enable Cartesian data channel '''

    def enableCartesianDataTransfer(self):
        self.writeVariable(b'enHeightAPI', struct.pack('B', 1))

    ''' Disables Cartesian data channel. '''

    def disableCartesianDataTransfer(self):
        self.writeVariable(b'enHeightAPI', struct.pack('B', 0))

    def getCartesianReduction(self):
        """ Reads the SOPAS variable enableCartesian (communication name: enCart) - only available on AG devices. """
        return struct.unpack('>?', self.readVariable(b'enCart'))[0]

    def getPolarReduction(self):
        """ Reads the SOPAS variable enablePolarScan (communication name: enPolar) - only available on AG devices. """
        return struct.unpack('>?', self.readVariable(b'enPolar'))[0]

    def getDepthMapDataTransfer(self):
        """ Reads the SOPAS variable enableDepthMapAPI (communication name: enDepthAPI) - only available on AG devices. """
        return struct.unpack('>?', self.readVariable(b'enDepthAPI'))[0]

    def getPolarDataTransfer(self):
        """ Reads the SOPAS variable enablePolarScanAPI (communication name: enPolarAPI) - only available on AG devices. """
        return struct.unpack('>?', self.readVariable(b'enPolarAPI'))[0]

    def getCartesianDataTransfer(self):
        """ Reads the SOPAS variable enableHeightMapAPI (communication name: enHeightAPI) - only available on AG devices. """
        return struct.unpack('>?', self.readVariable(b'enHeightAPI'))[0]

    def applySettings(self):
        self.invokeMethod(b'DeviceReInit')

    def setPowerMode(self, newPowerMode):
        """ Set the device power mode. """
        self.invokeMethod(b'SetPwrMod', struct.pack('>B', newPowerMode))

    def getPowerMode(self):
        """ Get the current device power mode. """
        rx = self.readVariable(b'CurPwrMode')
        return int(rx[-1])  # use unpack instead of int ?

    def setIntegrationTimeUs(self, newIntegrationTime):
        """ Set the device integration time in microseconds. """
        self.writeVariable(b'integrationTimeUs',
                           struct.pack('>I', newIntegrationTime))

    def getIntegrationTimeUs(self):
        """ Get the current device integration time in microseconds. """
        rx = self.readVariable(b'integrationTimeUs')
        intTime = struct.unpack('>I', rx)
        return intTime[0]

    def setIntegrationTimeUsColor(self, newIntegrationTime):
        """ Set the device integration time in microseconds. """
        self.writeVariable(b'integrationTimeUsColor',
                           struct.pack('>I', newIntegrationTime))

    def getIntegrationTimeUsColor(self):
        """ Get the current device integration time in microseconds. """
        rx = self.readVariable(b'integrationTimeUsColor')
        intTime = struct.unpack('>I', rx)
        return intTime[0]

    def setIdleTime(self, newIdleTime):
        """ Set the idle time """
        self.writeVariable(b'idleTime', struct.pack('>B', newIdleTime))

    def getIdleTime(self):
        """ Read the idle time value """
        rx = self.readVariable(b'idleTime')
        idleTime = struct.unpack('>B', rx)[0]
        return idleTime

    def setAcquisitionMode(self, newAcquisitionMode):
        """ Set the acquisition mode. """
        self.writeVariable(b'acquisitionMode',
                           struct.pack('>B', newAcquisitionMode))

    def getAcquisitionMode(self):
        """ Get the current acquisition mode. """
        rx = self.readVariable(b'acquisitionMode')
        return int(rx[-1])  # use unpack instead of int ?

    def setAcquisitionModeStereo(self, newAcquisitionMode):
        """ Set the acquisition mode. """
        self.writeVariable(b'acquisitionModeStereo',
                           struct.pack('>B', newAcquisitionMode))

    # method seems to be unused. delete??
    def getAcquisitionModeStereo(self):
        """ Get the current acquisition mode. """
        rx = self.readVariable(b'acquisitionModeStereo')
        return int(rx[-1])  # use unpack instead of int ?

    def setFrontendMode(self, newFrontendMode):
        """ Set the acquisition mode. """
        self.writeVariable(b'frontendMode', struct.pack('>B', newFrontendMode))

    def getFrontendMode(self) -> str:
        """ Get the current acquisition mode. """
        # Read the 'frontendMode' variable
        rx: bytes = self.readVariable(b'frontendMode')
        # Unpack the frontend mode from the received data
        frontendMode: int = int.from_bytes(rx, byteorder='big')

        # Map the frontend mode to its description
        frontendModeDict = {
            0: "CONTINUOUS",
            1: "STOP",
            2: "EXTERNALTRIGGER"
        }

        # Return the frontend mode description
        return frontendModeDict.get(frontendMode, "UNKNOWN")

    def getFrontendModeEnum(self) -> int:
        """ Get the current acquisition mode. """
        # Read the 'frontendMode' variable
        rx: bytes = self.readVariable(b'frontendMode')
        # Unpack the frontend mode from the received data
        frontendMode: int = int.from_bytes(rx, byteorder='big')

        return frontendMode

    def setNonAmbiguityMode(self, newNonAmbiguityMode):
        """ Set the device NonAmbiguity mode. """
        self.writeVariable(b'nareMode', struct.pack('>B', newNonAmbiguityMode))

    def getNonAmbiguityMode(self):
        """ Get the current NonAmbiguity mode. """
        rx = self.readVariable(b'nareMode')
        return int(rx[-1])  # use unpack instead of int ?

    def getAllMessageLogs(self):
        """ reads all device message logs """
        return {
            'MSdbg': self.getMessageLog('MSdbg'),
            'MSinfo': self.getMessageLog('MSinfo'),
            'MSwarn': self.getMessageLog('MSwarn'),
            'MSerr': self.getMessageLog('MSerr'),
            'MSfat': self.getMessageLog('MSfat')
        }

    def getMessageLog(self, ErrStructTypeName):
        """ reads a single device message log """

        def convert_seconds_to_time(seconds):
            seconds = int(seconds)
            hours = seconds // 3600
            seconds %= 3600
            minutes = seconds // 60
            seconds %= 60
            return f"{hours}:{minutes}:{seconds}"

        # define allowed var names and size of result array
        allowed_vars = {'MSdbg': 25, 'MSinfo': 25,
                        'MSwarn': 25, 'MSerr': 10, 'MSfat': 10}
        if not ErrStructTypeName in allowed_vars:
            raise RuntimeError(
                "failed to load \"%s\" message logs. See your CID file which variables returns <UserType TypeName=\"ErrStructType\" /> " % ErrStructTypeName)

        rx = self.readVariable(ErrStructTypeName.encode('utf-8'))

        # define the mapping from ErrorState to string
        error_state_mapping = {0: 'PERMANENT', 1: 'ACTIVE',
                               2: 'INACTIVE', 3: 'CLEAR', 4: 'UNKNOWN'}

        # see CID processed for data type details
        msg = []
        addr = 0
        for i in range(0, allowed_vars[ErrStructTypeName]):
            ErrorId, = struct.unpack('>I', rx[addr:addr + 4])
            addr += 4
            ErrorState, = struct.unpack('>I', rx[addr:addr + 4])
            addr += 4
            FirstTime_PwrOnCnt, = struct.unpack('>H', rx[addr:addr + 2])
            addr += 2
            FirstTime_OpSecs = convert_seconds_to_time(
                struct.unpack('>I', rx[addr:addr + 4])[0])
            addr += 4
            FirstTime_TimeOccur = convert_seconds_to_time(
                struct.unpack('>I', rx[addr:addr + 4])[0])
            addr += 4
            LastTime_PwrOnCnt, = struct.unpack('>H', rx[addr:addr + 2])
            addr += 2
            LastTime_OpSecs = convert_seconds_to_time(
                struct.unpack('>I', rx[addr:addr + 4])[0])
            addr += 4
            LastTime_TimeOccur = convert_seconds_to_time(
                struct.unpack('>I', rx[addr:addr + 4])[0])
            addr += 4
            NumberOccurance, = struct.unpack('>H', rx[addr:addr + 2])
            addr += 2
            ErrReserved, = struct.unpack('>H', rx[addr:addr + 2])
            addr += 2
            flxStrLen, = struct.unpack('>H', rx[addr:addr + 2])
            addr += 2
            ExtInfo = rx[addr:addr + flxStrLen]
            addr += flxStrLen
            entry = {
                "ErrorId": ErrorId,
                "ErrorState": error_state_mapping.get(ErrorState, 'UNKNOWN'),
                "FirstTime_PwrOnCnt": FirstTime_PwrOnCnt,
                "FirstTime_OpSecs": FirstTime_OpSecs,
                "FirstTime_TimeOccur": FirstTime_TimeOccur,
                "LastTime_PwrOnCnt": LastTime_PwrOnCnt,
                "LastTime_OpSecs": LastTime_OpSecs,
                "LastTime_TimeOccur": LastTime_TimeOccur,
                "NumberOccurance": NumberOccurance,
                "ErrReserved": ErrReserved,
                "ExtInfo": ExtInfo
            }
            if ErrorState > 0:
                msg.append(entry)
        return msg

    def clearMessageLogSickService(self):
        """  Clears all error messages, but not the fatal error messages. """
        rx = self.invokeMethod(b'mMSclrserviceerrmsg')
        return struct.unpack_from(">I", rx)[0]

    def clearMessageLog(self):
        """  Clears all error messages. """
        rx, _ = self.invokeMethod(b'mMSclrerrmsg')
        return struct.unpack_from(">I", rx)

    def checkIfMessageIsActive(self, ErrStructTypeName, messageID):
        """
        ///Description: Search for the message with the ID messageID and check if it is active
        ///Parameter:   ErrStructTypeName can be 'MSdbg', 'MSinfo', 'MSwarn', 'MSerr', 'MSfat'
        ///             required messageID
        ///Return:      True/False if message is active, number of occurances of the active message or zero
        """
        bMessageActive = False
        numberOfOccurances = 0
        extInfo = ""
        # read the selected messages
        messages = self.getMessageLog(ErrStructTypeName)
        # check if the required message is available and in active state
        for msg in messages:
            if msg['ErrorId'] == messageID:
                numberOfOccurances = msg['NumberOccurance']
                if msg['ErrorState'] == MESSAGE_STATE_ACTIVE:
                    bMessageActive = True
                    extInfo = msg['ExtInfo']
                    break
        return bMessageActive, numberOfOccurances, extInfo

    def debugSetError(self, errorID, extInfo, errorDetail):
        """ Injects a error with transferred parameters into the system. """
        rx = self.invokeMethod(b'DbgSetError',
                               struct.pack('>I', errorID) + self.pack_flexstring(extInfo) + struct.pack('>I', errorDetail))
        # no return value defined in SOPAS CID

    def login(self, newUserLevel, password):
        """ Logs in into the device with a given user level """
        if type(self.protocol) is Cola2:
            salt = None
            challenge = None
            if self.sulVersion == self.SULVERSION_1 or self.sulVersion == self.SULVERSION_UNKNOWN:
                try:
                    rx = self.invokeMethod(b"GetChallenge")
                    data = struct.unpack_from('>B16B', rx)
                    status = data[0]
                    challenge = data[1:]
                except RuntimeError as e:
                    if "parameter/return value buffer underflow" in str(e):
                        self.sulVersion = self.SULVERSION_2
                    else:
                        raise e
            if self.sulVersion == self.SULVERSION_2:
                rx = self.invokeMethod(
                    b"GetChallenge", struct.pack('>B', newUserLevel))
                data = struct.unpack('>B16B16B', rx)
                status = data[0]
                challenge = data[1:17]
                salt = data[17:]
            if status != 0:
                raise RuntimeError("Failed to get challenge to login")

            pwHash = self.calculateChallengeHash(
                self.USER_LEVEL_NAMES[newUserLevel], password, challenge, salt)
            rx = self.invokeMethod(b'SetUserLevel', struct.pack(
                ">32BB", *pwHash, newUserLevel))
            if int(rx[-1]) != 0:  # check the return byte for success | use unpack instead of int ?
                raise RuntimeError(
                    "Fail to login as user level %s with password %s" % (newUserLevel, password))
        else:
            pwHash = self.calculatePasswordHash(password)
            rx = self.invokeMethod(
                b'SetAccessMode', struct.pack('>BI', newUserLevel, pwHash))
            if int(rx[-1]) != 1:  # check the return byte for success | use unpack instead of int ?
                raise RuntimeError(
                    "Fail to login as user level %s with password %s" % (newUserLevel, password))

    def changeUserLevelPassword(self, userLevel, newPassword):
        """ Change the password of a given user level """
        newPwHash = self.calculatePasswordHash(newPassword)
        rx = self.invokeMethod(
            b'SetPassword', struct.pack('>BI', userLevel, newPwHash))
        return struct.unpack(b">?", rx)[0]

    def checkUserLevelPassword(self, userLevel, password):
        """ Checks if a password fits to a particular user level """
        pwHash = self.calculatePasswordHash(password)
        rx = self.invokeMethod(
            b'CheckPassword', struct.pack('>BI', userLevel, pwHash))
        return ord(rx[-1])

    def logout(self):
        self.invokeMethod(b'Run')

    def srt_login(self, userlevel, password):
        # type: (int, int) -> SrtLogin
        """ Returns a context manager for the login/logout handling.

        :param int userlevel: userlevel enum value
        :param int password: password hash

        :return: new context manager
        :rtype: SrtLogin"""

        return SrtLogin(self, userlevel, password)

    def getUserLevel(self):
        rx = self.invokeMethod(b'GetAccessMode')
        return struct.unpack('>I', rx[-1])

    def getIdent(self):
        """ Returns the device Name and Version identifier """
        rx = self.readVariable(b'DeviceIdent')
        offset = 0
        deviceName, offset = self.unpack_flexstring_from(rx, offset)
        deviceVersion, offset = self.unpack_flexstring_from(rx, offset)
        return (deviceName.decode('utf-8'), deviceVersion.decode('utf-8'))

    def getManufacturer(self) -> str:
        """ Returns the Manufacturer identifier """
        # Read the 'DImanf' variable
        rx: bytes = self.readVariable(b'DImanf')
        offset: int = 0
        # Unpack the manufacturer name from the received data
        manufacturerName: bytes
        manufacturerName, offset = self.unpack_flexstring_from(rx, offset)
        # Return the decoded manufacturer name
        return manufacturerName.decode('utf-8')

    def getFirmwareVersion(self) -> str:
        """ Returns the Firmware version of the device """
        # Read the 'FirmwareVersion' variable
        rx: bytes = self.readVariable(b'FirmwareVersion')
        offset: int = 0
        # Unpack the firmware version from the received data
        firmwareVersion: bytes
        firmwareVersion, offset = self.unpack_flexstring_from(rx, offset)
        # Return the decoded firmware version
        return firmwareVersion.decode('utf-8')

    def getOrderNumber(self) -> str:
        """ Returns the Order Number of the device """
        # Read the 'DIornr' variable
        rx: bytes = self.readVariable(b'DIornr')
        # Decode and return the order number
        return rx.decode('utf-8')

    def getSerialNumber(self) -> str:
        """ Returns the Serial Number of the device """
        # Read the 'SerialNumber' variable
        rx: bytes = self.readVariable(b'SerialNumber')
        offset: int = 0
        # Unpack the serial number from the received data
        serialNumber: bytes
        serialNumber, offset = self.unpack_flexstring_from(rx, offset)
        # Return the decoded serial number
        return serialNumber.decode('utf-8')

    def getCurrentJobId(self):
        currentJobId = self.readVariable(b"mjCurrentJobId")
        return struct.unpack('>H', currentJobId)[0]

    def getCurrentJobIdAscii(self, jobId):
        # returns the ascii conversion of the binary jobId
        return struct.unpack('>H', jobId)

    def selectJobByID(self, jobId):
        self.invokeMethod(b"mjSelectJob", struct.pack('>H', jobId))

    def cuboitGroupsToArray(self):
        # converts the given cuboit groups to an array of uint32
        # Each value contains the information if a cuboid belongs to a group or not (bitwise)
        return self.invokeMethod(b"GetAllCellGroups")

    def getAllCuboidCellsWithDetectionInfo(self):
        # get all cuboids with detection information as array of struct
        return self.invokeMethod(b"GetAllCellsWithDetectionInfo")

    def getRangeDimensions(self):
        rx = self.invokeMethod(b"GetRangeDimensions")
        return struct.unpack('>HH', rx)

    def setAutoExposure3DROI(self, left: int, right: int, top: int, bottom: int) -> None:
        """
        Sets the Region of Interest (ROI) for the 3D auto exposure.

        Parameters:
            left (int): The left boundary of the ROI.
            right (int): The right boundary of the ROI.
            top (int): The top boundary of the ROI.
            bottom (int): The bottom boundary of the ROI.
        """
        self.writeVariable(b'autoExposureROI', struct.pack(
            ">IIII", left, right, top, bottom))

    def setAutoExposureColorROI(self, left: int, right: int, top: int, bottom: int) -> None:
        """
        Sets the Region of Interest (ROI) for the color auto exposure.

        Parameters:
            left (int): The left boundary of the ROI.
            right (int): The right boundary of the ROI.
            top (int): The top boundary of the ROI.
            bottom (int): The bottom boundary of the ROI.
        """
        self.writeVariable(b'autoExposureColorROI', struct.pack(
            ">IIII", left, right, top, bottom))

    def setAutoWhiteBalanceROI(self, left: int, right: int, top: int, bottom: int) -> None:
        """
        Sets the Region of Interest (ROI) for the auto white balance.

        Parameters:
            left (int): The left boundary of the ROI.
            right (int): The right boundary of the ROI.
            top (int): The top boundary of the ROI.
            bottom (int): The bottom boundary of the ROI.
        """
        self.writeVariable(b'autoWhiteBalanceROI', struct.pack(
            ">IIII", left, right, top, bottom))

    def startAutoExposureParameterized(self, data):
        rx = self.invokeMethod(b"TriggerAutoExposureParameterized", data)
        return struct.unpack(">?", rx)[0]

    def getAutoExposureParameterizedRunning(self):
        rx = self.readVariable(b'autoExposureParameterizedRunning')
        return struct.unpack('>?', rx)[0]

    # Visionary-T Mini specific features
    def setFramePeriodUs(self, newFramePeriod):
        """ Set the device frame period in microseconds. """
        self.writeVariable(b'framePeriodUs', struct.pack('>I', newFramePeriod))

    def getFramePeriodUs(self):
        """ Get the current device frame period in microseconds. """
        rx = self.readVariable(b'framePeriodUs')
        framePeriod = struct.unpack('>I', rx)
        return framePeriod[0]

    def setDistanceMode(self, distanceMode):
        """ Only for Visionary S: Sets distance mode """
        self.writeVariable(b"distanceMode", struct.pack('B', distanceMode))

    # Diagnostics

    def getOpVoltageStatus(self) -> str:
        """ Returns the current OpVoltageStatus """
        # Read the 'OpVoltageStatus' variable
        rx: bytes = self.readVariable(b'OpVoltageStatus')
        # Unpack the OpVoltageStatus from the received data
        opVoltageStatus: int = int.from_bytes(rx, byteorder='big')

        # Map the OpVoltageStatus to its description
        opVoltageStatusDict = {
            0: "INVALID",
            1: "ERROR",
            2: "WARNING",
            3: "GOOD"
        }

        # Return the OpVoltageStatus description
        return opVoltageStatusDict.get(opVoltageStatus, "UNKNOWN")

    def getIlluminationActive(self) -> bool:
        """ Returns whether illumination is active """
        # Read the 'illuminationActive' variable
        rx: bytes = self.readVariable(b'illuminationActive')
        # Unpack the boolean value from the received data
        illuminationActive: bool = bool(int.from_bytes(rx, byteorder='big'))
        # Return the illumination status
        return illuminationActive

    def getTempLevel(self) -> str:
        """ Returns the current temperature level of the device """
        # Read the 'TmpLvl' variable
        rx: bytes = self.readVariable(b'TmpLvl')
        # Unpack the temperature level from the received data
        tempLevel: int = int.from_bytes(rx, byteorder='big')

        # Map the temperature level to its description
        tempLevelDict = {
            0: "INVALID",
            1: "ERROR",
            2: "WARNING",
            3: "GOOD"
        }

        # Return the temperature level description
        return tempLevelDict.get(tempLevel, "UNKNOWN")

    def getDigitalIOStatus(self) -> bool:
        """ Returns the status of the digital outputs """
        # Read the 'digitalIOStatus' variable
        rx: bytes = self.readVariable(b'digitalIOStatus')
        # Unpack the boolean value from the received data
        digitalIOStatus: bool = bool(int.from_bytes(rx, byteorder='big'))
        # Return the digital IO status
        return digitalIOStatus

    def getPowerOnCnt(self) -> int:
        """ Returns the number of power on cycles """
        # Read the 'ODpwrc' variable
        rx: bytes = self.readVariable(b'ODpwrc')
        # Unpack the power on count from the received data
        powerOnCnt: int = int.from_bytes(rx, byteorder='big')
        # Return the power on count
        return powerOnCnt

    def getOpHours(self) -> float:
        """ Returns the total number of operating hours since last service reset """
        # Read the 'ODoprh' variable
        rx: bytes = self.readVariable(b'ODoprh')
        # Unpack the operating hours from the received data
        opHours: float = struct.unpack('>f', rx)[0]
        # Return the operating hours
        return opHours

    def getDailyOpHours(self) -> float:
        """ Returns the runtime of the device since last power-on """
        # Read the 'ODopdaily' variable
        rx: bytes = self.readVariable(b'ODopdaily')
        # Unpack the daily operating hours from the received data
        dailyOpHours: float = struct.unpack('>f', rx)[0]
        # Return the daily operating hours
        return dailyOpHours

    # Electrical monitoring

    def getElectricalMonitoring(self) -> tuple:
        """ Returns all available electrical values """
        # Read the 'ElectricalMonitoring' variable
        rx: bytes = self.readVariable(b'ElectricalMonitoring')
        addr: int = 0
        # Unpack the LEDsCurrent from the received data
        LEDsCurrent, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Unpack the OperationVoltage from the received data
        OperationVoltage, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Unpack the MinimalVoltage from the received data
        MinimalVoltage, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Unpack the MaximalVoltage from the received data
        MaximalVoltage, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Return the electrical values as a list
        return (LEDsCurrent, OperationVoltage, MinimalVoltage, MaximalVoltage)

    def getElectricalLimits(self) -> tuple:
        """ Returns all available electrical limit values """
        # Read the 'ElectricalLimits' variable
        rx: bytes = self.readVariable(b'ElectricalLimits')
        addr: int = 0
        # Unpack the MinAllowedLEDsCurrent from the received data
        MinAllowedLEDsCurrent, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Unpack the MaxAllowedLEDsCurrent from the received data
        MaxAllowedLEDsCurrent, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Unpack the MinAllowedOpVoltage from the received data
        MinAllowedOpVoltage, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Unpack the MaxAllowedOpVoltage from the received data
        MaxAllowedOpVoltage, = struct.unpack('>f', rx[addr:addr + 4])
        addr += 4
        # Return the electrical limit values as a list
        return (MinAllowedLEDsCurrent, MaxAllowedLEDsCurrent, MinAllowedOpVoltage, MaxAllowedOpVoltage)

    # Temperatures

    def getSysTemperatureCurrentValue(self) -> int:
        """ Returns the current system temperature of the device """
        # Read the 'SysTemperatureCurrentValue' variable
        rx: bytes = self.readVariable(b'SysTemperatureCurrentValue')
        # Unpack the SysTemperatureCurrentValue from the received data
        SysTemperatureCurrentValue: int = struct.unpack('>h', rx)[0]
        # Convert the value to degrees Celsius
        SysTemperatureCurrentValue = SysTemperatureCurrentValue / 10.0
        # Return the system temperature
        return SysTemperatureCurrentValue

    def getTemperatureNames(self) -> List[str]:
        """ Returns the list of all names for the available temperatures """
        rx = self.readVariable(b'TemperatureNames')
        offset = 2  # Skip the first two bytes
        temperature_names = []
        while offset < len(rx):
            temp_name, offset = self.unpack_flexstring_from(rx, offset)
            temperature_names.append(temp_name.decode('utf-8'))
        return temperature_names

    def getTemperatureValues(self) -> List[float]:
        """ Returns the list of all available temperatures """
        rx: bytes = self.readVariable(b'TemperatureValues')
        offset = 2  # Skip the first two bytes
        temperature_values: List[float] = []
        while offset < len(rx):
            temp_value: int
            temp_value, = struct.unpack_from('>h', rx, offset)
            temp_value /= 10.0  # Convert to physical unit
            temperature_values.append(temp_value)
            offset += struct.calcsize('>h')
        return temperature_values

    # Digital Input/Output monitoring

    def getDoutOverload(self) -> bool:
        """ Returns the status of the digital output overload """
        # Read the 'DoOvrld' variable
        rx: bytes = self.readVariable(b'DoOvrld')
        # Unpack the doutOverload from the received data
        doutOverload: bool = bool(struct.unpack('>?', rx)[0])
        # Return the status of the digital output overload
        return doutOverload

    def getDoutPinError(self) -> dict:
        """ Returns the status of the digital output error due to a short circuit """
        # Read the 'DoPinErr' variable
        rx: bytes = self.readVariable(b'DoPinErr')
        # Unpack the doutPinError from the received data
        doutPinError: int = struct.unpack('>I', rx)[0]
        # Convert the integer to a dictionary of boolean values
        doutPinError_dict = {
            'Out1': bool(doutPinError & (1 << 0)),
            'Out2': bool(doutPinError & (1 << 1)),
            'Out3': bool(doutPinError & (1 << 2)),
            'Out4': bool(doutPinError & (1 << 3)),
            'Out5': bool(doutPinError & (1 << 4)),
            'Out6': bool(doutPinError & (1 << 5)),
            'Out7': bool(doutPinError & (1 << 6)),
            'Out8': bool(doutPinError & (1 << 7)),
        }
        # Return the status of the digital output error
        return doutPinError_dict

    # Ethernet monitoring

    def getEtherIPSpeedDuplex(self) -> str:
        """ Returns the Ethernet speed and duplex settings """
        # Read the 'EISpdDpx' variable
        rx: bytes = self.readVariable(b'EISpdDpx')
        # Unpack the EtherIPSpeedDuplex from the received data
        EtherIPSpeedDuplex: int = struct.unpack('>B', rx)[0]
        # Define the mapping of values to descriptions
        value_to_description = {
            0: "TX_AUTO",
            1: "TX_10MB_HALF",
            2: "TX_10MB_FULL",
            3: "TX_100MB_HALF",
            4: "TX_100MB_FULL",
            5: "TX_1000MB_HALF",
            6: "TX_1000MB_FULL",
        }
        # Convert the integer value to its corresponding description
        EtherIPSpeedDuplex = value_to_description.get(
            EtherIPSpeedDuplex, "Unknown")
        # Return the Ethernet speed and duplex settings
        return EtherIPSpeedDuplex

    def writeEeprom(self) -> bool:
        """ Writes all permanent parameters from the SOPAS mirror to the device memory. """
        rx = self.invokeMethod(b'mEEwriteall')
        return struct.unpack('>?', rx)[0]

    def loadFactoryDefaults(self):
        """ Resets all variables to their default value. """
        self.invokeMethod(b'mSCloadfacdef')

    def getBlobServerStatistics(self) -> list:
        """ reads BlobServerGetStatistics """
        # define struct names
        struct_names = ['Decoding', 'Sending', 'ScalingTime', 'SendingTime']
        rx = self.invokeMethod(b'BlobServerGetStatistics')
        # see CID processed for data type details
        stats = []
        addr = 0
        for i in range(0, 2):  # length of Levels array is 2
            for strct in struct_names:
                if strct in ['Decoding', 'Sending']:
                    NumImages, = struct.unpack('>I', rx[addr:addr + 4])
                    addr += 4
                    NumErrors, = struct.unpack('>I', rx[addr:addr + 4])
                    addr += 4
                    if strct == 'Sending':
                        NumInactive, = struct.unpack('>I', rx[addr:addr + 4])
                        addr += 4
                elif strct in ['ScalingTime', 'SendingTime']:
                    MinTime_ms, = struct.unpack('>f', rx[addr:addr + 4])
                    addr += 4
                    AvgTime_ms, = struct.unpack('>f', rx[addr:addr + 4])
                    addr += 4
                    MaxTime_ms, = struct.unpack('>f', rx[addr:addr + 4])
                    addr += 4
                entry = {
                    "Level": i,
                    "Var": strct,
                    "NumImages": NumImages,
                    "NumErrors": NumErrors,
                    "NumInactive": NumInactive if strct == 'Sending' else None,
                    "MinTime_ms": MinTime_ms if strct in ['ScalingTime', 'SendingTime'] else None,
                    "AvgTime_ms": AvgTime_ms if strct in ['ScalingTime', 'SendingTime'] else None,
                    "MaxTime_ms": MaxTime_ms if strct in ['ScalingTime', 'SendingTime'] else None,
                }
                stats.append(entry)
        return stats
