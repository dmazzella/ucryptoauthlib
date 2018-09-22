# -*- coding: utf-8 -*-
from ucryptoauthlib import constant as ATCA_CONSTANTS
from ucryptoauthlib import status as ATCA_STATUS
from ucryptoauthlib.packet import ATCAPacket


class ATECCBasic(object):
    """ ATECCBasic """

    def execute(self, packet):
        """ Abstract execute method """
        raise NotImplementedError()

    def is_error(self, data):
        if data[0] == 0x04:  # error packets are always 4 bytes long
            return ATCA_STATUS.decode_error(data[1])
        else:
            return ATCA_STATUS.ATCA_SUCCESS, "Success"

    def at_crc(self, data, polynom=0x8005):
        crc = 0x0000
        for d in data:
            for b in range(8):
                data_bit = 1 if d & 1 << b else 0
                crc_bit = crc >> 15 & 0xff
                crc = crc << 1 & 0xffff
                if data_bit != crc_bit:
                    crc = crc ^ polynom & 0xffff
        return bytes([crc & 0x00ff, crc >> 8 & 0xff])

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Info command             #
    ###########################################################################

    def atcab_info(self, mode=ATCA_CONSTANTS.INFO_MODE_REVISION, param2=0):
        packet = ATCAPacket(
            ATCA_CONSTANTS.ATCA_INFO,
            param1=mode,
            param2=param2,
            # response_data=bytearray(ATCA_CONSTANTS.INFO_SIZE)
        )
        self.execute(packet)
        return packet
