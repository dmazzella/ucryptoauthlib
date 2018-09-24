# -*- coding: utf-8 -*-
from cryptoauthlib import constant as ATCA_CONSTANTS
from cryptoauthlib import status as ATCA_STATUS
from cryptoauthlib.packet import ATCAPacket


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

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Info command             #
    ###########################################################################

    def atcab_info_base(self, mode=0):
        packet = ATCAPacket(
            opcode=ATCA_CONSTANTS.ATCA_INFO,
            param1=mode
        )
        self.execute(packet)
        return packet

    def atcab_info(self):
        return self.atcab_info_base(ATCA_CONSTANTS.INFO_MODE_REVISION)

    ###########################################################################
    #            CryptoAuthLib Basic API methods for SHA command              #
    ###########################################################################

    def atcab_sha_base(self, mode=0, data=b''):

        txsize = 0
        cmd_mode = mode & ATCA_CONSTANTS.SHA_MODE_MASK
        if cmd_mode in (
            ATCA_CONSTANTS.SHA_MODE_SHA256_START,
            ATCA_CONSTANTS.SHA_MODE_HMAC_START,
            ATCA_CONSTANTS.SHA_MODE_SHA256_PUBLIC
        ):
            txsize = ATCA_CONSTANTS.ATCA_CMD_SIZE_MIN
        elif cmd_mode in (
            ATCA_CONSTANTS.SHA_MODE_SHA256_UPDATE,
            ATCA_CONSTANTS.SHA_MODE_SHA256_END,
            ATCA_CONSTANTS.SHA_MODE_HMAC_END
        ):
            txsize = ATCA_CONSTANTS.ATCA_CMD_SIZE_MIN + len(data)
        else:
            raise ValueError("bad params")

        packet = ATCAPacket(
            txsize=txsize,
            opcode=ATCA_CONSTANTS.ATCA_SHA,
            param1=mode,
            param2=len(data),
            request_data=data
        )
        self.execute(packet)
        return packet

    def atcab_sha(self, data):
        packet = self.atcab_sha_base(ATCA_CONSTANTS.SHA_MODE_SHA256_START)
        packet = self.atcab_sha_base(ATCA_CONSTANTS.SHA_MODE_SHA256_UPDATE, data)
        packet = self.atcab_sha_base(ATCA_CONSTANTS.SHA_MODE_SHA256_END)
        return packet

