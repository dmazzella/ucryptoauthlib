# -*- coding: utf-8 -*-
# pylint: disable=E0401
# pylint: disable=E0602
import micropython
import ustruct
import utime
from ubinascii import hexlify
from cryptoauthlib import constant as ATCA


class ATCAPacket(object):
    """ ATCAPacket """

    struct_format = "<BBBH{:d}s"

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
        self.txsize = txsize
        self.opcode = opcode
        self.param1 = param1
        self.param2 = param2
        self.device = device
        self._request_data = request_data
        self._response_data = response_data or bytearray(ATCA.ATCA_CMD_SIZE_MAX)

    def __str__(self):
        return (
            "<{:s}"
            " txsize={:d}"
            " opcode=0x{:02x}"
            " param1=0x{:02x}"
            " param2=0x{:04x}"
            " request_data={:s}"
            " response_data={:s}"
            " device={:s}>"
        ).format(
            self.__class__.__name__,
            self.txsize,
            self.opcode,
            self.param1,
            self.param2,
            hexlify(self.request_data),
            hexlify(self.response_data),
            self.device
        )

    def __repr__(self):
        return str(self)

    def __getitem__(self, i):
        return self._response_data[i]

    def __getattr__(self, name):
        if name == "delay":
            return ATCA.EXECUTION_TIME.get(
                self.device, "ATECC508A"
            ).get(self.opcode, 250)
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

    def to_buffer(self):
        params = self.response_data or bytearray(self.txsize)
        ustruct.pack_into(
            ATCAPacket.struct_format.format(len(self.request_data)),
            params,
            0,
            self.txsize,
            self.opcode,
            self.param1,
            self.param2,
            self.request_data
        )
        self.at_crc(params, self.txsize-ATCA.ATCA_CRC_SIZE)
        return params

    @micropython.viper
    def at_crc(self, src: ptr8, length: int) -> int:
        polynom = 0x8005
        crc = 0
        for i in range(length):
            d = src[i]
            for b in range(8):
                data_bit = 1 if d & 1 << b else 0
                crc_bit = crc >> 15 & 0xff
                crc = crc << 1 & 0xffff
                if data_bit != crc_bit:
                    crc = crc ^ polynom & 0xffff
        src[length] = crc & 0x00ff
        src[length+1] = crc >> 8 & 0xff
        return crc

    # def at_crc(self, src, length):
    #     polynom = 0x8005
    #     crc = 0
    #     for i in range(length):
    #         d = src[i]
    #         for b in range(8):
    #             data_bit = 1 if d & 1 << b else 0
    #             crc_bit = crc >> 15 & 0xff
    #             crc = crc << 1 & 0xffff
    #             if data_bit != crc_bit:
    #                 crc = crc ^ polynom & 0xffff
    #     src[length] = crc & 0x00ff
    #     src[length+1] = crc >> 8 & 0xff
    #     return crc
