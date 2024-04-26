# -*- coding: utf-8 -*-
"""
Namespace for CoLa error mappings.

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


class ColaErrors:
    __ERROR_MAP = {
        0x0001: "access denied",
        0x0002: "unknown method",
        0x0003: "unknown variable",
        0x0004: "local condition failed",
        0x0005: "invalid data",
        0x0006: "unknown command",
        0x0007: "parameter/return value buffer overflow",
        0x0008: "parameter/return value buffer underflow",
        0x0009: "parameter type error",
        0x000A: "variable write access denied",
        0x000B: "unknown command for nameserver",
        0x000C: "unknown CoLa command",
        0x000D: "method server busy",
        0x000E: "flex array/string out of bounds",
        0x000F: "unknown event",
        0x0010: "CoLaA value overflow",
        0x0011: "invalid character in CoLaA packet",
        0x0012: "OsAI no message",
        0x0013: "OsAI no answer message",
        0x0014: "Internal error, e.g. AppSpace SRT method does not return a retval",
        0x0015: "HubAddress corrupted",
        0x0016: "HubAddress decoding",
        0x0017: "HubAddress address exceeded",
        0x0018: "HubAddress blank expected",
        0x0019: "AsyncMethods are suppressed",
        0x001A: "reserved",
        0x001B: "reserved",
        0x001C: "reserved",
        0x001D: "reserved",
        0x001E: "reserved",
        0x001F: "reserved",
        0x0020: "ComplexArrays are not supported",
        0x0021: "no ressources for new session",
        0x0022: "unknown session ID",
        0x0023: "cannot connect",
        0x0024: "invalid port ID",
        0x0025: "scan already active",
        0x0026: "out of timers",
        0x0027: "reserved",
        0x0028: "reserved",
        0x0029: "reserved",
        0x002A: "reserved",
        0x002B: "reserved",
        0x002C: "reserved",
        0x002D: "reserved",
        0x002E: "reserved",
        0x002F: "reserved",
        0x0030: "reserved",
        0x0031: "reserved",
        0x0032: "reserved",
        0x0033: "reserved",
        0x0034: "reserved",
        0x0035: "reserved",
        0x0036: "reserved",
        0x0037: "reserved",
        0x0038: "reserved",
        0x0039: "reserved",
        0x003A: "reserved",
        0x003B: "reserved",
        0x003C: "reserved",
        0x003D: "reserved",
        0x003E: "reserved",
        0x003F: "reserved",
        # SRTpp errors
        0x0040: "CID node error",
        0x0041: "CID leaf error",
        0x0042: "CID struct error",
        0x0043: "CID type select error",
        0x0044: "CID array error",
        0x0045: "SRTpp processor error",
        0x0046: "SRTpp repository error",
        0x0047: "SRT factory error",
        0x0048: "SRT factory xml error",
        0x0049: "IXML parser error",
        0x004A: "addressing by index not supported by SRTpp",
        0x004C: "no ICID method handler registered",
        0x004D: "method handler expected parameter which wasn't provided",
        0x004E: "method handler expected return value which wasn't provided",
        0x004F: "CID enum error",
        0x0050: "can't acquire ClientID",
        0x0051: "CID VirtualMemory / CIDBankSwitching error",
        0x0052: "CIDCplxLeaf unknown buffer",
        0x0053: "CIDCplxLeaf out of buffer"
    }

    @staticmethod
    def get_error_message(error_code):
        error_message = ColaErrors.__ERROR_MAP.get(error_code)
        raise RuntimeError("Cola Error: {}".format(error_message))
