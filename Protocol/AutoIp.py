#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense


import ipaddress
import logging
import platform
import random
import socket
import struct
import time
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

PAYLOAD_OFFSET = 16  # offset where data starts in the response


def to_hex(str_value):
    """ just to produce a readable output of the device responses """
    return ' '.join(hex(x) for x in str_value)


class AutoIpDevice:
    def __init__(self, colaVersion, deviceIdent, serialNumber, orderNumber, authVersion, macAddress, colaPort, ipAddress, netmask, gateway, dhcpEnabled, configTimeMs):
        self.colaVersion = colaVersion
        self.deviceIdent = deviceIdent
        self.serialNumber = serialNumber
        self.orderNumber = orderNumber
        self.authVersion = authVersion
        self.macAddress = macAddress
        self.colaPort = colaPort
        self.ipAddress = ipAddress
        self.netmask = netmask
        self.gateway = gateway
        self.dhcpEnabled = dhcpEnabled
        self.configTimeMs = configTimeMs


class AutoIp:
    def __init__(self, serverIp='192.168.1.100/24'):
        self.AUTOIP_PORT = 30718  # see: Sopas AutoIp Specification
        self.TIMEOUT = 1.1  # as in spec, devices may reply within 1020ms
        ip4 = ipaddress.ip_interface(serverIp)
        self.serverIp = ip4.ip.exploded
        self.serverNetMask = ip4.netmask.exploded
        net = ipaddress.ip_network(serverIp, False)
        self.serverBroadcastIp = net.broadcast_address.exploded

    def openSocket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.settimeout(self.TIMEOUT)
        self.socket.bind((self.serverIp, self.AUTOIP_PORT))
        if platform.system() == 'Linux':
            self.rxsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            self.rxsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.rxsock.settimeout(self.TIMEOUT)
            self.rxsock.bind((b'255.255.255.255', self.AUTOIP_PORT))

    def writeSocket(self, msg):
        self.socket.sendto(msg, (b'255.255.255.255', self.AUTOIP_PORT))
        self.socket.sendto(msg, (self.serverBroadcastIp, self.AUTOIP_PORT))

    def readSocket(self):
        try:
            rx = self.socket.recv(4096)
            logger.debug("received {} bytes".format(len(rx)))
        except socket.timeout as timeoutException:
            if platform.system() == 'Linux':
                rx = self.rxsock.recv(4096)
                logger.debug("received {} bytes".format(len(rx)))
            else:
                # raise initial timeout exception on windows
                raise timeoutException
        return rx

    def closeSocket(self):
        self.socket.close()
        if platform.system() == 'Linux':
            self.rxsock.close()

    def generateTeleId(self):
        random.seed(time.time())
        return struct.pack('>I', random.randint(0, 0xffffffff))

    def decodeXmlResponse(self, rpl):
        '''Decode a CoLa-A response packet (based on XML)'''

        net_scan_result = ET.fromstring(rpl)
        items = {}
        for item in net_scan_result.iter('Item'):
            items[item.get('key')] = item.get('value')

        dev = AutoIpDevice(
            1,
            items['DeviceType'],
            items['SerialNumber'],
            items['OrderNumber'],
            1,
            net_scan_result.get('MACAddr'),
            items['HostPortNo'],
            items['IPAddress'],
            items['IPMask'],
            items['IPGateway'],
            items['DHCPClientEnabled'] == 'TRUE',
            items['IPConfigDuration'])
        return dev

    def decodeBinaryResponse(self, rpl):
        '''Decode a binary (CoLa-B / 2) response'''

        offset = 0
        authVersion = 1
        ipAddress = None
        netmask = None
        gateway = None
        dhcpEnabled = None
        macAddress = None
        configTime = None

        deviceInfoVersion, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2

        cidNameLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        cidName = rpl[offset:offset + cidNameLen]
        offset += cidNameLen
        logger.debug("cidName: {}".format(cidName))

        cidMajorVersion, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        cidMinorVersion, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        cidPatchVersion, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        cidBuildVersion, = struct.unpack('>L', rpl[offset:offset + 4])
        offset += 4
        cidVersionClassifier, = struct.unpack('>B', rpl[offset:offset + 1])
        offset += 1
        logger.debug(
            "CidVersion: {}.{}.{}.{}{}".format(cidMajorVersion, cidMinorVersion, cidPatchVersion, cidBuildVersion,
                                               cidVersionClassifier))

        deviceState, = struct.unpack('>B', rpl[offset:offset + 1])
        offset += 1

        reqUserAction, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2

        deviceNameLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        deviceName = rpl[offset:offset + deviceNameLen]
        offset += deviceNameLen
        logger.debug("deviceName: {}".format(deviceName))

        appNameLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        appName = rpl[offset:offset + appNameLen]
        offset += appNameLen
        logger.debug("appName: {}".format(appName))

        projNameLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        projName = rpl[offset:offset + projNameLen]
        offset += projNameLen
        logger.debug("projName: {}".format(projName))

        serialNumberLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        serialNumber = rpl[offset:offset + serialNumberLen]
        offset += serialNumberLen
        logger.debug("serialNum: {}".format(serialNumber))

        typeCodeLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        typeCode = rpl[offset:offset + typeCodeLen]
        offset += typeCodeLen
        logger.debug("typeCode: {}".format(typeCode))

        firmwareVersionLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        firmwareVersion = rpl[offset:offset + firmwareVersionLen]
        offset += firmwareVersionLen
        logger.debug("firmwareVersion: {}".format(firmwareVersion))

        orderNumberLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        orderNumber = rpl[offset:offset + orderNumberLen]
        offset += orderNumberLen
        logger.debug("orderNumber: {}".format(orderNumber))

        flags = struct.unpack('>B', rpl[offset:offset + 1])
        offset += 1

        auxArrayLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        logger.debug("auxArrayLen: {}".format(auxArrayLen))
        for i in range(auxArrayLen):
            key = rpl[offset:offset + 4]
            offset += 4
            innerArrayLen, = struct.unpack('>H', rpl[offset:offset + 2])
            offset += 2
            innerArray = rpl[offset:offset + innerArrayLen]
            if (key == b'AutV') and (innerArray == b'1.0.0.0R'):
                authVersion = 2
            logger.debug("  key: {}, innerArrayLen: {}".format(
                key, innerArrayLen))
            for j in range(innerArrayLen):
                v, = struct.unpack('>B', rpl[offset:offset + 1])
                offset += 1
                logger.debug("    v: {}".format(hex(v)))

        scanIfLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        logger.debug("scanIfLen: {}".format(scanIfLen))
        for i in range(scanIfLen):
            ifaceNum, = struct.unpack('>H', rpl[offset:offset + 2])
            offset += 2
            ifaceNameLen, = struct.unpack('>H', rpl[offset:offset + 2])
            offset += 2
            ifaceName = rpl[offset:offset + ifaceNameLen]
            offset += ifaceNameLen
            logger.debug("  ifaceNum: {}, ifaceName: {}".format(
                ifaceNum, ifaceName))

        comSettingsLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        logger.debug("comSettingsLen: {}".format(comSettingsLen))
        for i in range(comSettingsLen):
            key = rpl[offset:offset + 4]
            offset += 4
            innerArrayLen, = struct.unpack('>H', rpl[offset:offset + 2])
            offset += 2
            logger.debug("  key: {}, innerArrayLen: {}".format(
                key, innerArrayLen))
            if key == b"EMAC":
                macAddress = rpl[offset:offset + 6]
                offset += 6
                logger.debug("  EMAC: {}".format(
                    "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", macAddress)))
            elif key == b"EIPa":
                ipAddress = rpl[offset:offset + 4]
                offset += 4
                logger.debug("  EIPa: {}".format("%u.%u.%u.%u" %
                             struct.unpack("BBBB", ipAddress)))
            elif key == b"ENMa":
                netmask = rpl[offset:offset + 4]
                offset += 4
                logger.debug("  ENMa: {}".format("%u.%u.%u.%u" %
                             struct.unpack("BBBB", netmask)))
            elif key == b"EDGa":
                gateway = rpl[offset:offset + 4]
                offset += 4
                logger.debug("  EDGa: {}".format("%u.%u.%u.%u" %
                             struct.unpack("BBBB", gateway)))
            elif key == b"EDhc":
                dhcpEnabled = rpl[offset:offset + 1] != 0
                offset += 1
                logger.debug("  EDhc: {}".format(dhcpEnabled))
            elif key == b"ECDu":
                configTime, = struct.unpack('>L', rpl[offset:offset + 4])
                offset += 4
                logger.debug("  ECDu: {}".format(configTime))
            else:
                for j in range(innerArrayLen):
                    v, = struct.unpack('>B', rpl[offset:offset + 1])
                    offset += 1
                    logger.debug("  v: {}".format(hex(v)))

        endPointsLen, = struct.unpack('>H', rpl[offset:offset + 2])
        offset += 2
        logger.debug("endPointsLen: {}".format(endPointsLen))
        ports = []
        for i in range(endPointsLen):
            colaVersion, = struct.unpack('>B', rpl[offset:offset + 1])
            offset += 1
            logger.debug("colaVersion: {}".format(colaVersion))
            innerArrayLen, = struct.unpack('>H', rpl[offset:offset + 2])
            offset += 2
            logger.debug("innerArrayLen: {}".format(innerArrayLen))
            for j in range(innerArrayLen):
                key = rpl[offset:offset + 4]
                offset += 4
                mostInnerArrayLen, = struct.unpack(
                    '>H', rpl[offset:offset + 2])
                offset += 2
                logger.debug("  key: {}, mostInnerArrayLen: {}".format(
                    key, mostInnerArrayLen))
                if key == b"DPNo":  # PortNumber [UInt]
                    p, = struct.unpack('>H', rpl[offset:offset + 2])
                    offset += 2
                    logger.debug("  DPNo: {}".format(p))
                    ports.append({"protocol": colaVersion, "port": p})
                else:
                    for k in range(mostInnerArrayLen):
                        v, = struct.unpack('>B', rpl[offset:offset + 1])
                        offset += 1
                        logger.debug("  v: {}".format(hex(v)))

        dev = AutoIpDevice(
            2,
            cidName.decode('latin1'),
            serialNumber.decode('latin1'),
            orderNumber.decode('latin1'),
            authVersion,
            "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack(
                "BBBBBB", macAddress),
            ports[0]['port'],
            "%d.%d.%d.%d" % struct.unpack("BBBB", ipAddress),
            "%d.%d.%d.%d" % struct.unpack("BBBB", netmask),
            "%d.%d.%d.%d" % struct.unpack("BBBB", gateway),
            dhcpEnabled,
            configTime * 1000)
        return dev

    def scan(self):
        """ Sends an AutoIp brodcast and listen for responses.
            Return a list of AutoIpDevice
        """
        CMD_NETSCAN = b"\x10"
        RPL_NETSCAN = b"\x90"
        RPL_NETSCAN_COLA2 = b"\x95"

        self.openSocket()
        try:
            TELE_ID = self.generateTeleId()

            msg = CMD_NETSCAN
            msg += b"\x00"  # not defined / rfu
            msg += b"\x00\x08"  # for serverIp and serverNetMask
            msg += b"\xff\xff\xff\xff\xff\xff"  # mac == ff:ff:ff:ff:ff:ff per specification
            msg += TELE_ID
            msg += b"\x01\x00"  # 0x01 (Cloa Scan identifier) + 0x00 (RFU)
            msg += struct.pack('>4B', *[int(x)
                               for x in self.serverIp.split('.')])
            msg += struct.pack('>4B', *[int(x)
                               for x in self.serverNetMask.split('.')])

            self.writeSocket(msg)
            logger.debug(
                "broadcast sent! with telegram id: {}".format(to_hex(TELE_ID)))

            # send braodcast and gather replies
            replies = []
            macs = []
            try:
                while (1):
                    rx = self.readSocket()
                    if bytes([rx[0]]) == RPL_NETSCAN or bytes([rx[0]]) == RPL_NETSCAN_COLA2:
                        replyLength, = struct.unpack('>H', rx[2:4])
                        replyMac = rx[4:10]
                        replyTeleId = rx[10:14]
                        if replyTeleId == TELE_ID:
                            logger.debug("Reply-> len:{} mac:{} teleId:{}".format(replyLength, to_hex(replyMac),
                                                                                  to_hex(replyTeleId)))
                            if not replyMac in macs:
                                macs.append(replyMac)
                                if bytes([rx[0]]) == RPL_NETSCAN:
                                    replies.append(
                                        rx[PAYLOAD_OFFSET:PAYLOAD_OFFSET + replyLength])
                                elif bytes([rx[0]]) == RPL_NETSCAN_COLA2:
                                    # use TELE_ID as marker that this is a binary coded reply
                                    replies.append(
                                        TELE_ID + rx[PAYLOAD_OFFSET:PAYLOAD_OFFSET + replyLength])
                    time.sleep(0.01)
            except socket.timeout:
                logger.debug(
                    "No more answers after {} seconds".format(self.TIMEOUT))

            # parse replies and return dict with results
            foundDevices = []
            for rpl in replies:
                if rpl[0:4] == TELE_ID:
                    foundDevices.append(
                        self.decodeBinaryResponse(rpl[len(TELE_ID):]))
                else:
                    foundDevices.append(self.decodeXmlResponse(rpl))
            return foundDevices

        except Exception as e:
            logger.debug(
                "AutoIP scan: General error occurred: {}".format(str(e)))

        finally:
            self.closeSocket()

    def assign(self, dstMac, colaVer, ipAddr='192.168.1.10', ipMask='255.255.255.0', ipGw='0.0.0.0', dhcp=False):
        CMD_IPCONFIG = b"\x11"
        RPL_IPCONFIG = b"\x91"

        if int(colaVer) == 1:
            top = ET.Element('IPconfig')
            top.set('MACAddr', dstMac)
            ET.SubElement(top, 'Item', {'key': 'IPAddress', 'value': ipAddr})
            ET.SubElement(top, 'Item', {'key': 'IPMask', 'value': ipMask})
            ET.SubElement(top, 'Item', {'key': 'IPGateway', 'value': ipGw})
            ET.SubElement(
                top, 'Item', {'key': 'DHCPClientEnabled', 'value': str(dhcp).upper()})
            payload = b'<?xml version="1.0" encoding="UTF-8"?>'
            payload += ET.tostring(top)
        elif int(colaVer) == 2:
            payload = socket.inet_aton(ipAddr)
            payload += socket.inet_aton(ipMask)
            payload += socket.inet_aton(ipGw)
            payload += struct.pack('>B', dhcp)
        else:
            raise RuntimeError(
                "Parameter colaVer must be either 1 or 2 but is: {}".format(colaVer))

        self.openSocket()
        try:
            TELE_ID = self.generateTeleId()

            msg = CMD_IPCONFIG
            msg += b"\x00"  # not defined / rfu
            msg += struct.pack('>H', len(payload))
            msg += struct.pack('>6B', *[int(x, 16) for x in dstMac.split(':')])
            msg += TELE_ID
            msg += b"\x01\x00"  # cola scan / rfu
            msg += payload

            self.writeSocket(msg)
            logger.debug(
                "IPCONFIG message sent! with telegram id: {}".format(to_hex(TELE_ID)))

            try:
                while (1):
                    rx = self.readSocket()
                    logger.debug("received {} bytes".format(len(rx)))
                    if bytes([rx[0]]) == RPL_IPCONFIG:
                        replyLength, = struct.unpack('>H', rx[2:4])
                        replyMac = rx[4:10]
                        replyTeleId = rx[10:14]
                        if replyTeleId == TELE_ID:
                            logger.debug(
                                "RPL_IPCONFIG -> len:{} mac:{} teleId:{}".format(replyLength, to_hex(replyMac),
                                                                                 to_hex(replyTeleId)))
                            return True
                    time.sleep(0.01)
            except socket.timeout:
                logger.debug(
                    "No more RPL_IPCONFIG answers after {} seconds".format(self.TIMEOUT))

        finally:
            self.closeSocket()
        return False
