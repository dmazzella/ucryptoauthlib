# -*- coding: utf-8 -*-
# pylint: disable=E0401
from binascii import hexlify

import ustruct
import utime
from micropython import const
from cryptoauthlib import constant as ATCA


class ATCAPacket(object):
    """ ATCAPacket """

    struct_format = "<BBH"
    struct_size = ustruct.calcsize(struct_format)

    def __init__(
        self, opcode, param1=0, param2=0,
        request_data=b'',
        response_data=bytearray(ATCA.ATCA_CMD_SIZE_MAX),
        device="ATECC508A"
    ):
        self._opcode = opcode
        self._param1 = param1
        self._param2 = param2
        self._request_data = request_data
        self._response_data = response_data
        self._device = device
        self._delay = ATCA.EXECUTION_TIME[device].get(opcode, 2000)

    def __str__(self):
        return (
            "<{:s}"
            " opcode=0x{:02x}"
            " param1=0x{:02x}"
            " param2=0x{:04x}"
            " request_data={:s}"
            " response_data={:s}>"
        ).format(
            self.__class__.__name__,
            self.opcode,
            self.param1,
            self.param2,
            hexlify(self.request_data),
            hexlify(self.response_data)
        )

    def __getattr__(self, name):
        if name == "opcode":
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
    def from_buffer(buffer, device="ATECC508A"):
        opcode, param1, param2 = ustruct.unpack_from(
            ATCAPacket.struct_format,
            buffer[:ATCAPacket.struct_size]
        )
        request_data = buffer[ATCAPacket.struct_size:]
        return ATCAPacket(
            opcode,
            param1=param1,
            param2=param2,
            request_data=request_data,
            device=device
        )

    def to_buffer(self):
        return ustruct.pack(
            ATCAPacket.struct_format,
            self.opcode,
            self.param1,
            self.param2
        ) + self.request_data
