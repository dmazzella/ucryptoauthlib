# -*- coding: utf-8 -*-
# pylint: disable=E0401
import binascii
from binascii import hexlify

import ustruct
import utime
from cryptoauthlib import constant as ATCA
from micropython import const


class ATCAPacket(object):
    """ ATCAPacket """

    struct_format = "<BBBH"
    struct_size = ustruct.calcsize(struct_format)

    def __init__(
        self,
        txsize=ATCA.ATCA_CMD_SIZE_MIN,
        opcode=0,
        param1=0,
        param2=0,
        request_data=b'',
        response_data=b'',
        device="ATECC508A"
    ):
        self._txsize = txsize
        self._opcode = opcode
        self._param1 = param1
        self._param2 = param2
        self._request_data = request_data
        self._response_data = response_data or bytearray(
            ATCA.ATCA_CMD_SIZE_MAX)
        self._device = device
        self._delay = ATCA.EXECUTION_TIME[device].get(opcode, 2000)

    def __str__(self):
        return (
            "<{:s}"
            " txsize={:d}"
            " opcode=0x{:02x}"
            " param1=0x{:02x}"
            " param2=0x{:04x}"
            " request_data={:s}"
            " response_data={:s}>"
        ).format(
            self.__class__.__name__,
            self.txsize,
            self.opcode,
            self.param1,
            self.param2,
            hexlify(self.request_data),
            hexlify(self.response_data)
        )

    def __getattr__(self, name):
        if name == "txsize":
            return self._txsize
        elif name == "opcode":
            return self._opcode
        elif name == "param1":
            return self._param1
        elif name == "param2":
            return self._param2
        elif name == "delay":
            return self._delay
        elif name == "request_length":
            return len(self._request_data)
        elif name == "request_data":
            return self._request_data
        elif name == "request_data_mv":
            return memoryview(self._request_data)
        elif name == "response_length":
            return len(self._response_data)
        elif name == "response_data":
            return self._response_data
        elif name == "response_data_mv":
            return memoryview(self._response_data)
        else:
            raise AttributeError(name)

    @staticmethod
    def from_buffer(buffer, response_data=b'', device="ATECC508A"):
        buffer_mv = memoryview(buffer)
        txsize, opcode, param1, param2 = ustruct.unpack_from(
            ATCAPacket.struct_format,
            buffer_mv[:ATCAPacket.struct_size]
        )
        request_data = buffer_mv[ATCAPacket.struct_size:]
        return ATCAPacket(
            txsize=txsize,
            opcode=opcode,
            param1=param1,
            param2=param2,
            request_data=request_data,
            response_data=response_data,
            device=device
        )

    def to_buffer(self):
        params = ustruct.pack(
            ATCAPacket.struct_format,
            self.txsize,
            self.opcode,
            self.param1,
            self.param2
        ) + self.request_data
        params += self.at_crc(params)
        return params

    def at_crc(self, data, polynom=0x8005):
        crc = 0
        for d in data:
            for b in range(8):
                data_bit = 1 if d & 1 << b else 0
                crc_bit = crc >> 15 & 0xff
                crc = crc << 1 & 0xffff
                if data_bit != crc_bit:
                    crc = crc ^ polynom & 0xffff
        return bytes([crc & 0x00ff, crc >> 8 & 0xff])
