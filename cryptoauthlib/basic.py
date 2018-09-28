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
    #          CryptoAuthLib Basic API methods for CheckMAC command           #
    ###########################################################################

    ###########################################################################
    #           CryptoAuthLib Basic API methods for Counter command           #
    ###########################################################################

    ###########################################################################
    #          CryptoAuthLib Basic API methods for DeriveKey command          #
    ###########################################################################

    ###########################################################################
    #            CryptoAuthLib Basic API methods for ECDH command             #
    ###########################################################################

    ###########################################################################
    #           CryptoAuthLib Basic API methods for GenDig command            #
    ###########################################################################

    ###########################################################################
    #           CryptoAuthLib Basic API methods for GenKey command            #
    ###########################################################################

    ###########################################################################
    #            CryptoAuthLib Basic API methods for HMAC command             #
    ###########################################################################

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
    #             CryptoAuthLib Basic API methods for KDF command             #
    ###########################################################################

    ###########################################################################
    #             CryptoAuthLib Basic API methods for Lock command            #
    ###########################################################################

    ###########################################################################
    #             CryptoAuthLib Basic API methods for MAC command             #
    ###########################################################################

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Nonce command            #
    ###########################################################################

    ###########################################################################
    #          CryptoAuthLib Basic API methods for PrivWrite command          #
    ###########################################################################

    ###########################################################################
    #           CryptoAuthLib Basic API methods for Random command            #
    ###########################################################################

    def atcab_random(self):
        packet = ATCAPacket(
            opcode=ATCA_CONSTANTS.ATCA_RANDOM,
            param1=ATCA_CONSTANTS.RANDOM_SEED_UPDATE,
        )
        self.execute(packet)
        return packet

    ###########################################################################
    #             CryptoAuthLib Basic API methods for Read command            #
    ###########################################################################

    ###########################################################################
    #          CryptoAuthLib Basic API methods for SecureBoot command         #
    ###########################################################################

    ###########################################################################
    #           CryptoAuthLib Basic API methods for SelfTest command          #
    ###########################################################################

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
        bs = ATCA_CONSTANTS.ATCA_SHA256_BLOCK_SIZE
        d_mv = memoryview(data)
        packet = self.atcab_sha_base(ATCA_CONSTANTS.SHA_MODE_SHA256_START)
        for i in range(0, len(d_mv), bs):
            lb = not len(d_mv) % bs
            b = d_mv[i:i + bs]
            m = ATCA_CONSTANTS.SHA_MODE_SHA256_UPDATE
            if len(b) == bs:
                packet = self.atcab_sha_base(m, b)
            if len(b) < bs or lb:
                b = b'' if lb else b
                m = ATCA_CONSTANTS.SHA_MODE_SHA256_END
                packet = self.atcab_sha_base(m, b)
        return packet

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Sign command             #
    ###########################################################################

    ###########################################################################
    #         CryptoAuthLib Basic API methods for UpdateExtra command         #
    ###########################################################################

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Verify command           #
    ###########################################################################

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Write command            #
    ###########################################################################
