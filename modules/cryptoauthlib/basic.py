# -*- coding: utf-8 -*-
from cryptoauthlib import constant as ATCA_CONSTANTS
from cryptoauthlib import exceptions as ATCA_EXCEPTIONS
from cryptoauthlib import status as ATCA_STATUS
from cryptoauthlib.packet import ATCAPacket

_ATCA_VERSION = "20190104"
_BYTES_LIKE_OBJECT = (bytes, bytearray, memoryview)


class ATECCBasic(object):
    """ ATECCBasic """

    _device = None

    def execute(self, packet):
        """ Abstract execute method """
        raise NotImplementedError()

    def is_error(self, data):
        # error packets are always 4 bytes long
        if data[ATCA_CONSTANTS.ATCA_COUNT_IDX] == 0x04:
            return ATCA_STATUS.decode_error(
                data[ATCA_CONSTANTS.ATCA_RSP_DATA_IDX]
            )
        else:
            return ATCA_STATUS.ATCA_SUCCESS, None

    def atcab_version(self):
        return _ATCA_VERSION

    def atcab_get_addr(self, zone, slot=0, block=0, offset=0):
        mem_zone = zone & ATCA_CONSTANTS.ATCA_ZONE_MASK
        if mem_zone not in (
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            ATCA_CONSTANTS.ATCA_ZONE_DATA,
            ATCA_CONSTANTS.ATCA_ZONE_OTP
        ):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if slot < 0 or slot > 15:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        addr = 0
        offset = offset & 0x07
        if mem_zone in (
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            ATCA_CONSTANTS.ATCA_ZONE_OTP
        ):
            addr = block << 3
            addr = addr | offset
        elif mem_zone == ATCA_CONSTANTS.ATCA_ZONE_DATA:
            addr = slot << 3
            addr = addr | offset
            addr = addr | block << 8

        return addr

    def atcab_get_zone_size(self, zone, slot=0):
        if zone not in (
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            ATCA_CONSTANTS.ATCA_ZONE_DATA,
            ATCA_CONSTANTS.ATCA_ZONE_OTP
        ):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if slot < 0 or slot > 15:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if zone == ATCA_CONSTANTS.ATCA_ZONE_CONFIG:
            return 128
        elif zone == ATCA_CONSTANTS.ATCA_ZONE_OTP:
            return 64
        elif zone == ATCA_CONSTANTS.ATCA_ZONE_DATA:
            if slot < 8:
                return 36
            elif slot == 8:
                return 412
            elif slot < 16:
                return 72

    ###########################################################################
    #          CryptoAuthLib Basic API methods for CheckMAC command           #
    ###########################################################################

    def atcab_checkmac(self, mode, key_id, challenge, response,  other_data):
        raise NotImplementedError("atcab_checkmac")

    ###########################################################################
    #           CryptoAuthLib Basic API methods for Counter command           #
    ###########################################################################

    def atcab_counter(self, mode, counter_id):
        raise NotImplementedError("atcab_counter")

    def atcab_counter_increment(self, counter_id):
        raise NotImplementedError("atcab_counter_increment")

    def atcab_counter_read(self, counter_id):
        raise NotImplementedError("atcab_counter_read")

    ###########################################################################
    #          CryptoAuthLib Basic API methods for DeriveKey command          #
    ###########################################################################

    def atcab_derivekey(self, mode, key_id, mac):
        raise NotImplementedError("atcab_derivekey")

    ###########################################################################
    #            CryptoAuthLib Basic API methods for ECDH command             #
    ###########################################################################

    def atcab_ecdh_base(self, mode, key_id, public_key):
        raise NotImplementedError("atcab_ecdh_base")

    def atcab_ecdh(self, key_id, public_key):
        raise NotImplementedError("atcab_ecdh")

    def atcab_ecdh_enc(self, key_id, public_key, read_key, read_key_id):
        raise NotImplementedError("atcab_ecdh_enc")

    def atcab_ecdh_ioenc(self, key_id, public_key, io_key):
        raise NotImplementedError("atcab_ecdh_ioenc")

    def atcab_ecdh_tempkey(self, public_key):
        raise NotImplementedError("atcab_ecdh_tempkey")

    def atcab_ecdh_tempkey_ioenc(self, public_key, io_key):
        raise NotImplementedError("atcab_ecdh_tempkey_ioenc")

    ###########################################################################
    #           CryptoAuthLib Basic API methods for GenDig command            #
    ###########################################################################

    def atcab_gendig(self, zone, key_id, other_data):
        raise NotImplementedError("atcab_gendig")

    ###########################################################################
    #           CryptoAuthLib Basic API methods for GenKey command            #
    ###########################################################################

    def atcab_genkey_base(self, mode, key_id, other_data=None):

        txsize = 0
        if mode & ATCA_CONSTANTS.GENKEY_MODE_PUBKEY_DIGEST:
            txsize = ATCA_CONSTANTS.GENKEY_COUNT_DATA
        else:
            txsize = ATCA_CONSTANTS.GENKEY_COUNT

        has_other_data = isinstance(other_data, _BYTES_LIKE_OBJECT)
        data = other_data if has_other_data else b''

        packet = ATCAPacket(
            txsize=txsize,
            opcode=ATCA_CONSTANTS.ATCA_GENKEY,
            param1=mode,
            param2=key_id,
            request_data=data
        )
        self.execute(packet)
        return packet

    def atcab_genkey(self, key_id):
        return self.atcab_genkey_base(ATCA_CONSTANTS.GENKEY_MODE_PRIVATE, key_id)

    def atcab_get_pubkey(self, key_id):
        return self.atcab_genkey_base(ATCA_CONSTANTS.GENKEY_MODE_PUBLIC, key_id)

    ###########################################################################
    #            CryptoAuthLib Basic API methods for HMAC command             #
    ###########################################################################

    def atcab_hmac(self, mode, key_id):
        raise NotImplementedError("atcab_hmac")

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

    def atcab_kdf(self, mode, key_id, details, message):
        raise NotImplementedError("atcab_kdf")

    ###########################################################################
    #             CryptoAuthLib Basic API methods for Lock command            #
    ###########################################################################

    def atcab_lock(self, mode, crc=0):
        packet = ATCAPacket(
            txsize=ATCA_CONSTANTS.LOCK_COUNT,
            opcode=ATCA_CONSTANTS.ATCA_LOCK,
            param1=mode,
            param2=crc
        )
        self.execute(packet)
        return packet

    def atcab_lock_config_zone(self):
        return self.atcab_lock(
            ATCA_CONSTANTS.LOCK_ZONE_NO_CRC | ATCA_CONSTANTS.LOCK_ZONE_CONFIG
        )

    def atcab_lock_config_zone_crc(self, crc):
        return self.atcab_lock(ATCA_CONSTANTS.LOCK_ZONE_CONFIG, crc)

    def atcab_lock_data_zone(self):
        return self.atcab_lock(
            ATCA_CONSTANTS.LOCK_ZONE_NO_CRC | ATCA_CONSTANTS.LOCK_ZONE_DATA
        )

    def atcab_lock_data_zone_crc(self, crc):
        return self.atcab_lock(ATCA_CONSTANTS.LOCK_ZONE_DATA, crc)

    def atcab_lock_data_slot(self, slot):
        if slot < 0 or slot > 15:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        return self.atcab_lock((slot << 2) | ATCA_CONSTANTS.LOCK_ZONE_DATA_SLOT)

    ###########################################################################
    #             CryptoAuthLib Basic API methods for MAC command             #
    ###########################################################################

    def atcab_mac(self, mode, key_id, challenge):
        raise NotImplementedError("atcab_mac")

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Nonce command            #
    ###########################################################################

    def atcab_nonce_base(self, mode, zero=0, numbers=None):
        nonce_mode = mode & ATCA_CONSTANTS.NONCE_MODE_MASK
        if nonce_mode not in (
            ATCA_CONSTANTS.NONCE_MODE_SEED_UPDATE,
            ATCA_CONSTANTS.NONCE_MODE_NO_SEED_UPDATE,
            ATCA_CONSTANTS.NONCE_MODE_PASSTHROUGH
        ):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if not isinstance(numbers, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        txsize = 0
        if nonce_mode in (
            ATCA_CONSTANTS.NONCE_MODE_SEED_UPDATE,
            ATCA_CONSTANTS.NONCE_MODE_NO_SEED_UPDATE
        ):
            txsize = ATCA_CONSTANTS.NONCE_COUNT_SHORT
        elif nonce_mode == ATCA_CONSTANTS.NONCE_MODE_PASSTHROUGH:
            nonce_mode_input = mode & ATCA_CONSTANTS.NONCE_MODE_INPUT_LEN_MASK
            if nonce_mode_input == ATCA_CONSTANTS.NONCE_MODE_INPUT_LEN_64:
                txsize = ATCA_CONSTANTS.NONCE_COUNT_LONG_64
            else:
                txsize = ATCA_CONSTANTS.NONCE_COUNT_LONG
        else:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        n_mv = memoryview(numbers)
        if len(n_mv) < txsize-ATCA_CONSTANTS.ATCA_CMD_SIZE_MIN:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        packet = ATCAPacket(
            txsize=txsize,
            opcode=ATCA_CONSTANTS.ATCA_NONCE,
            param1=mode,
            param2=zero,
            request_data=n_mv[:txsize-ATCA_CONSTANTS.ATCA_CMD_SIZE_MIN]
        )

        self.execute(packet)
        return packet

    def atcab_nonce(self, numbers=None):
        return self.atcab_nonce_base(
            ATCA_CONSTANTS.NONCE_MODE_PASSTHROUGH,
            numbers=numbers
        )

    def atcab_nonce_load(self, target, numbers=None):
        if not isinstance(numbers, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        mode = ATCA_CONSTANTS.NONCE_MODE_PASSTHROUGH
        mode = mode | (ATCA_CONSTANTS.NONCE_MODE_TARGET_MASK & target)

        if len(numbers) == 32:
            mode = mode | ATCA_CONSTANTS.NONCE_MODE_INPUT_LEN_32
        elif len(numbers) == 64:
            mode = mode | ATCA_CONSTANTS.NONCE_MODE_INPUT_LEN_64
        else:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        return self.atcab_nonce_base(mode, numbers=numbers)

    def atcab_nonce_rand(self, numbers=None):
        return self.atcab_nonce_base(
            ATCA_CONSTANTS.NONCE_MODE_SEED_UPDATE,
            numbers=numbers
        )

    def atcab_challenge(self, numbers=None):
        return self.atcab_nonce_base(
            ATCA_CONSTANTS.NONCE_MODE_PASSTHROUGH,
            numbers=numbers
        )

    def atcab_challenge_seed_update(self, numbers=None):
        return self.atcab_nonce_base(
            ATCA_CONSTANTS.NONCE_MODE_SEED_UPDATE,
            numbers=numbers
        )

    ###########################################################################
    #          CryptoAuthLib Basic API methods for PrivWrite command          #
    ###########################################################################

    def atcab_priv_write(self, key_id, priv_key, write_key_id, write_key):
        raise NotImplementedError("atcab_priv_write")

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

    def atcab_read_zone(self, zone, slot=0, block=0, offset=0, length=0):
        if length not in (
            ATCA_CONSTANTS.ATCA_WORD_SIZE,
            ATCA_CONSTANTS.ATCA_BLOCK_SIZE
        ):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        addr = self.atcab_get_addr(zone, slot=slot, block=block, offset=offset)

        if length == ATCA_CONSTANTS.ATCA_BLOCK_SIZE:
            zone = zone | ATCA_CONSTANTS.ATCA_ZONE_READWRITE_32

        packet = ATCAPacket(
            opcode=ATCA_CONSTANTS.ATCA_READ,
            param1=zone,
            param2=addr
        )
        self.execute(packet)
        return packet

    def atcab_read_serial_number(self):
        return self.atcab_read_zone(
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            length=ATCA_CONSTANTS.ATCA_BLOCK_SIZE
        )

    def atcab_read_bytes_zone(self, zone, slot=0, block=0, offset=0, length=0):
        zone_size = self.atcab_get_zone_size(zone, slot=slot)

        if offset + length > zone_size:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        packets = []

        BS = ATCA_CONSTANTS.ATCA_BLOCK_SIZE
        WS = ATCA_CONSTANTS.ATCA_WORD_SIZE

        r_sz = BS
        d_idx = r_idx = r_of = c_blk = c_of = 0
        c_blk = offset // BS
        while d_idx < length:
            if r_sz == BS and zone_size - c_blk * BS < BS:
                r_sz = WS
                c_of = ((d_idx + offset) // WS) % (BS // WS)

            packet = self.atcab_read_zone(
                zone,
                slot=slot,
                block=c_blk,
                offset=c_of,
                length=r_sz
            )
            packets.append(packet)

            r_of = c_blk * BS + c_of * WS
            r_idx = offset - r_of if r_of < offset else 0
            d_idx += length - d_idx if length - d_idx < r_sz - r_idx else r_sz - r_idx

            if r_sz == BS:
                c_blk += 1
            else:
                c_of += 1

        return packets

    def atcab_is_slot_locked(self, slot):
        # Read the word with the lock bytes
        # ( SlotLock[2], RFU[2] ) ( config block = 2, word offset = 6 )
        packet = self.atcab_read_zone(
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            slot=0,
            block=2,
            offset=6,
            length=ATCA_CONSTANTS.ATCA_WORD_SIZE
        )
        return bool((packet[0+1] | (packet[1+1] << 8) & (1 << slot)) == 0)

    def atcab_is_locked(self, zone):
        if zone not in (
            ATCA_CONSTANTS.LOCK_ZONE_CONFIG,
            ATCA_CONSTANTS.LOCK_ZONE_DATA
        ):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        # Read the word with the lock bytes
        # (UserExtra, Selector, LockValue, LockConfig) (config block = 2, word offset = 5)
        packet = self.atcab_read_zone(
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            slot=0,
            block=2,
            offset=5,
            length=ATCA_CONSTANTS.ATCA_WORD_SIZE
        )
        if zone == ATCA_CONSTANTS.LOCK_ZONE_CONFIG:
            return bool(packet[3+1] != 0x55)
        elif zone == ATCA_CONSTANTS.LOCK_ZONE_DATA:
            return bool(packet[2+1] != 0x55)

    def atcab_read_config_zone(self):
        return self.atcab_read_bytes_zone(
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            length=ATCA_CONSTANTS.ATCA_ECC_CONFIG_SIZE
        )

    def atcab_read_enc(self, key_id, block, data, enc_key, enc_key_id):
        raise NotImplementedError("atcab_read_enc")

    def atcab_cmp_config_zone(self, config_data):
        raise NotImplementedError("atcab_cmp_config_zone")

    def atcab_read_sig(self, slot):
        raise NotImplementedError("atcab_read_sig")

    def atcab_read_pubkey(self, slot):
        # Check the value of the slot. Only slots 8 to 15 are large enough to store a public key
        if slot < 8 or slot > 15:
            raise ATCA_EXCEPTIONS.BadArgumentError(
                "Only slots 8 to 15 are large enough to store a public key")

        # The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
        #
        # | Block 1                     | Block 2                                      | Block 3       |
        # | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

        ZD = ATCA_CONSTANTS.ATCA_ZONE_DATA
        BS = ATCA_CONSTANTS.ATCA_BLOCK_SIZE
        PKD = ATCA_CONSTANTS.ATCA_PUB_KEY_PAD
        KS = ATCA_CONSTANTS.ATCA_KEY_SIZE

        public_key = b''
        packet = self.atcab_read_zone(ZD, slot=slot, block=0, length=BS)
        public_key += packet[1:-2]
        packet = self.atcab_read_zone(ZD, slot=slot, block=1, length=BS)
        public_key += packet[1:-2]
        packet = self.atcab_read_zone(ZD, slot=slot, block=2, length=BS)
        public_key += packet[1:-2]

        return public_key[PKD:PKD+KS] + public_key[KS+PKD+PKD:KS+PKD+PKD+KS]

    ###########################################################################
    #          CryptoAuthLib Basic API methods for SecureBoot command         #
    ###########################################################################

    def atcab_secureboot(self, mode, param2, digest, signature):
        raise NotImplementedError("atcab_secureboot")

    def atcab_secureboot_mac(self, mode, digest, signature, num_in, io_key):
        raise NotImplementedError("atcab_secureboot_mac")

    ###########################################################################
    #           CryptoAuthLib Basic API methods for SelfTest command          #
    ###########################################################################

    def atcab_selftest(self, mode, param2=0):
        if self._device != "ATECC608A":
            raise ATCA_EXCEPTIONS.UnsupportedDeviceError("atcab_selftest")
        packet = ATCAPacket(
            opcode=ATCA_CONSTANTS.ATCA_SELFTEST,
            param1=mode,
            param2=param2
        )
        self.execute(packet)
        RSP_DATA_IDX = ATCA_CONSTANTS.ATCA_RSP_DATA_IDX
        return packet[RSP_DATA_IDX] & int(not mode) == ATCA_STATUS.ATCA_SUCCESS

    ###########################################################################
    #            CryptoAuthLib Basic API methods for SHA command              #
    ###########################################################################

    def atcab_sha_base(self, mode=0, data=b'', key_slot=None):
        if not isinstance(data, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

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
            raise ATCA_EXCEPTIONS.BadArgumentError()

        packet = ATCAPacket(
            txsize=txsize,
            opcode=ATCA_CONSTANTS.ATCA_SHA,
            param1=mode,
            param2=len(data) if not isinstance(key_slot, int) else key_slot,
            request_data=data
        )
        self.execute(packet)
        return packet

    def atcab_sha(self, data):
        bs = ATCA_CONSTANTS.ATCA_SHA256_BLOCK_SIZE
        d_mv = memoryview(data)
        packet = self.atcab_sha_base(ATCA_CONSTANTS.SHA_MODE_SHA256_START)
        chunks, rest = divmod(len(d_mv), bs)
        for chunk in range(chunks):
            m = ATCA_CONSTANTS.SHA_MODE_SHA256_UPDATE
            b = d_mv[chunk:chunk + bs]
            packet = self.atcab_sha_base(m, b)
        m = ATCA_CONSTANTS.SHA_MODE_SHA256_END
        b = d_mv[chunks * bs:chunks * bs + rest]
        packet = self.atcab_sha_base(m, b)
        return packet

    def atcab_sha_hmac(self, data, key_slot, target):
        raise NotImplementedError("atcab_sha_hmac")

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Sign command             #
    ###########################################################################

    def atcab_sign_base(self, mode, key_id):
        packet = ATCAPacket(
            txsize=ATCA_CONSTANTS.SIGN_COUNT,
            opcode=ATCA_CONSTANTS.ATCA_SIGN,
            param1=mode,
            param2=key_id
        )
        self.execute(packet)
        return packet

    def atcab_sign(self, key_id, message):
        nonce_target = ATCA_CONSTANTS.NONCE_MODE_TARGET_TEMPKEY
        sign_source = ATCA_CONSTANTS.SIGN_MODE_SOURCE_TEMPKEY

        # Load message into device
        if self._device == "ATECC608A":
            # Use the Message Digest Buffer for the ATECC608A
            nonce_target = ATCA_CONSTANTS.NONCE_MODE_TARGET_MSGDIGBUF
            sign_source = ATCA_CONSTANTS.SIGN_MODE_SOURCE_MSGDIGBUF

        self.atcab_nonce_load(nonce_target, message)
        return self.atcab_sign_base(
            ATCA_CONSTANTS.SIGN_MODE_EXTERNAL | sign_source,
            key_id
        )

    def atcab_sign_internal(self, key_id, is_invalidate=False, is_full_sn=False):
        mode = ATCA_CONSTANTS.SIGN_MODE_INTERNAL
        if is_invalidate:
            mode = mode | ATCA_CONSTANTS.SIGN_MODE_INVALIDATE

        if is_full_sn:
            mode = mode | ATCA_CONSTANTS.SIGN_MODE_INCLUDE_SN

        return self.atcab_sign_base(mode, key_id)

    ###########################################################################
    #         CryptoAuthLib Basic API methods for UpdateExtra command         #
    ###########################################################################

    def atcab_updateextra(self, mode, value):
        packet = ATCAPacket(
            opcode=ATCA_CONSTANTS.ATCA_UPDATE_EXTRA,
            param1=mode,
            param2=value
        )
        self.execute(packet)
        return packet

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Verify command           #
    ###########################################################################

    def atcab_verify(self, mode, key_id, signature, public_key=None, other_data=None, mac=None):
        if not isinstance(signature, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        verify_mode = (mode & ATCA_CONSTANTS.VERIFY_MODE_MASK)

        VME = ATCA_CONSTANTS.VERIFY_MODE_EXTERNAL
        has_public_key = isinstance(public_key, _BYTES_LIKE_OBJECT)
        if verify_mode == VME and not has_public_key:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        VMV = ATCA_CONSTANTS.VERIFY_MODE_VALIDATE
        VMI = ATCA_CONSTANTS.VERIFY_MODE_INVALIDATE
        has_other_data = isinstance(other_data, _BYTES_LIKE_OBJECT)
        if verify_mode in (VMV, VMI) and not has_other_data:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        txsize = 0
        if verify_mode == ATCA_CONSTANTS.VERIFY_MODE_STORED:
            txsize = ATCA_CONSTANTS.VERIFY_256_STORED_COUNT
        elif verify_mode in (ATCA_CONSTANTS.VERIFY_MODE_VALIDATE_EXTERNAL,
                             ATCA_CONSTANTS.VERIFY_MODE_EXTERNAL):
            txsize = ATCA_CONSTANTS.VERIFY_256_EXTERNAL_COUNT
        elif verify_mode in (ATCA_CONSTANTS.VERIFY_MODE_VALIDATE,
                             ATCA_CONSTANTS.VERIFY_MODE_INVALIDATE):
            txsize = ATCA_CONSTANTS.VERIFY_256_VALIDATE_COUNT

        SS = ATCA_CONSTANTS.ATCA_SIG_SIZE
        PKS = ATCA_CONSTANTS.ATCA_PUB_KEY_SIZE
        VODS = ATCA_CONSTANTS.VERIFY_OTHER_DATA_SIZE
        data_size = SS
        if has_public_key:
            data_size += PKS
        elif has_other_data:
            data_size += VODS

        data = bytearray(data_size)

        data[0:SS] = signature
        if has_public_key:
            data[SS:SS+PKS] = public_key
        elif has_other_data:
            data[SS:SS+VODS] = other_data

        packet = ATCAPacket(
            txsize=txsize,
            opcode=ATCA_CONSTANTS.ATCA_VERIFY,
            param1=mode,
            param2=key_id,
            request_data=data
        )
        self.execute(packet)
        return packet

    def atcab_verify_extern(self, message, signature, public_key):
        if not isinstance(message, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if not isinstance(signature, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if not isinstance(public_key, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        nonce_target = ATCA_CONSTANTS.NONCE_MODE_TARGET_TEMPKEY
        verify_source = ATCA_CONSTANTS.VERIFY_MODE_SOURCE_TEMPKEY

        # Load message into device
        if self._device == "ATECC608A":
            # Use the Message Digest Buffer for the ATECC608A
            nonce_target = ATCA_CONSTANTS.NONCE_MODE_TARGET_MSGDIGBUF
            verify_source = ATCA_CONSTANTS.VERIFY_MODE_SOURCE_MSGDIGBUF

        self.atcab_nonce_load(nonce_target, message)
        try:
            packet = self.atcab_verify(
                ATCA_CONSTANTS.VERIFY_MODE_EXTERNAL | verify_source,
                ATCA_CONSTANTS.VERIFY_KEY_P256,
                signature,
                public_key
            )
            return packet[1] == ATCA_STATUS.ATCA_SUCCESS
        except ATCA_EXCEPTIONS.CheckmacVerifyFailedError:
            # Verify failed, but command succeeded
            return False

    def atcab_verify_extern_mac(self, message, signature, public_key, num_in, io_key, is_verified):
        raise NotImplementedError("atcab_verify_extern_mac")

    def atcab_verify_stored(self, message, signature, key_id):
        if not isinstance(message, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if not isinstance(signature, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        nonce_target = ATCA_CONSTANTS.NONCE_MODE_TARGET_TEMPKEY
        verify_source = ATCA_CONSTANTS.VERIFY_MODE_SOURCE_TEMPKEY

        # Load message into device
        if self._device == "ATECC608A":
            # Use the Message Digest Buffer for the ATECC608A
            nonce_target = ATCA_CONSTANTS.NONCE_MODE_TARGET_MSGDIGBUF
            verify_source = ATCA_CONSTANTS.VERIFY_MODE_SOURCE_MSGDIGBUF

        self.atcab_nonce_load(nonce_target, message)
        try:
            packet = self.atcab_verify(
                ATCA_CONSTANTS.VERIFY_MODE_STORED | verify_source,
                key_id,
                signature
            )
            return packet[1] == ATCA_STATUS.ATCA_SUCCESS
        except ATCA_EXCEPTIONS.CheckmacVerifyFailedError:
            # Verify failed, but command succeeded
            return False

    def atcab_verify_stored_mac(self, message, signature, key_id, num_in, io_key, is_verified):
        raise NotImplementedError("atcab_verify_stored_mac")

    def atcab_verify_validate(self,  key_id, signature, other_data, is_verified):
        raise NotImplementedError("atcab_verify_validate")

    def atcab_verify_invalidate(self,  key_id, signature, other_data, is_verified):
        raise NotImplementedError("atcab_verify_invalidate")

    ###########################################################################
    #            CryptoAuthLib Basic API methods for Write command            #
    ###########################################################################

    def atcab_write(self, zone, address, value=None, mac=None):
        if not isinstance(value, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        txsize = ATCA_CONSTANTS.ATCA_CMD_SIZE_MIN
        data = bytearray(64)
        if zone & ATCA_CONSTANTS.ATCA_ZONE_READWRITE_32:
            # 32-byte write
            data[0:32] = value
            txsize += ATCA_CONSTANTS.ATCA_BLOCK_SIZE
            # Only 32-byte writes can have a MAC
            if isinstance(mac, _BYTES_LIKE_OBJECT):
                data[32:64] = mac
                txsize += ATCA_CONSTANTS.WRITE_MAC_SIZE
        else:
            # 4-byte write
            data[0:4] = value
            txsize += ATCA_CONSTANTS.ATCA_WORD_SIZE

        packet = ATCAPacket(
            txsize=txsize,
            opcode=ATCA_CONSTANTS.ATCA_WRITE,
            param1=zone,
            param2=address,
            request_data=data[:txsize-ATCA_CONSTANTS.ATCA_CMD_SIZE_MIN]
        )
        self.execute(packet)
        return packet

    def atcab_write_zone(self, zone, slot=0, block=0, offset=0, data=None):
        if not isinstance(data, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        length = len(data)
        if length not in (
            ATCA_CONSTANTS.ATCA_WORD_SIZE,
            ATCA_CONSTANTS.ATCA_BLOCK_SIZE
        ):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        if length == ATCA_CONSTANTS.ATCA_BLOCK_SIZE:
            zone = zone | ATCA_CONSTANTS.ATCA_ZONE_READWRITE_32

        addr = self.atcab_get_addr(zone, slot=slot, block=block, offset=offset)
        return self.atcab_write(zone, addr, data)

    def atcab_write_bytes_zone(self, zone, slot=0, offset=0, data=None):
        if not isinstance(data, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        zone_size = self.atcab_get_zone_size(zone, slot=slot)

        length = len(data)
        if offset + length > zone_size:
            raise ATCA_EXCEPTIONS.BadArgumentError()

        packets = []

        BS = ATCA_CONSTANTS.ATCA_BLOCK_SIZE
        WS = ATCA_CONSTANTS.ATCA_WORD_SIZE
        ZC = ATCA_CONSTANTS.ATCA_ZONE_CONFIG

        d_idx = 0
        c_blk = offset // BS
        c_wrd = (offset % BS) // WS
        d_mv = memoryview(data)
        while d_idx < length:
            # The last item makes sure we handle the selector, user extra, and lock bytes in the config properly
            if c_wrd == 0 and length - d_idx >= BS and not (zone == ZC and c_blk == 2):
                packet = self.atcab_write_zone(
                    zone,
                    slot=slot,
                    block=c_blk,
                    offset=0,
                    data=d_mv[d_idx:d_idx+BS]
                )
                packets.append(packet)
                d_idx += BS
                c_blk += 1
            else:
                # Skip trying to change UserExtra, Selector, LockValue and LockConfig which require the UpdateExtra command to change
                if not (zone == ZC and c_blk == 2 and c_wrd == 5):
                    packet = self.atcab_write_zone(
                        zone,
                        slot=slot,
                        block=c_blk,
                        offset=c_wrd,
                        data=d_mv[d_idx:d_idx+WS]
                    )
                    packets.append(packet)
                d_idx += WS
                c_wrd += 1
                if c_wrd == BS // WS:
                    c_blk += 1
                    c_wrd = 0

        return packets

    def atcab_write_pubkey(self, slot, public_key):
        if not isinstance(public_key, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        # Check the value of the slot. Only slots 8 to 15 are large enough to store a public key
        if slot < 8 or slot > 15:
            raise ATCA_EXCEPTIONS.BadArgumentError(
                "Only slots 8 to 15 are large enough to store a public key")

        public_key_formatted = bytearray(72)

        # The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
        #
        # | Block 1                     | Block 2                                      | Block 3       |
        # | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

        PKD = ATCA_CONSTANTS.ATCA_PUB_KEY_PAD
        KS = ATCA_CONSTANTS.ATCA_KEY_SIZE

        # Copy X to padded position
        public_key_formatted[PKD:PKD+KS] = public_key[0:KS]
        # Copy Y to padded position
        public_key_formatted[KS+PKD+PKD:KS+PKD+PKD+KS] = public_key[KS:KS+KS]

        packets = self.atcab_write_bytes_zone(
            ATCA_CONSTANTS.ATCA_ZONE_DATA,
            slot=slot,
            data=public_key_formatted
        )

        return packets

    def atcab_write_config_zone(self, config_data):
        if not isinstance(config_data, _BYTES_LIKE_OBJECT):
            raise ATCA_EXCEPTIONS.BadArgumentError()

        config_size = self.atcab_get_zone_size(ATCA_CONSTANTS.ATCA_ZONE_CONFIG)

        # Write config zone excluding UserExtra and Selector
        packets = self.atcab_write_bytes_zone(
            ATCA_CONSTANTS.ATCA_ZONE_CONFIG,
            slot=0,
            offset=16,
            data=config_data[16:config_size - 16]
        )

        # Write the UserExtra and Selector. This may fail if either value is already non-zero.
        packet = self.atcab_updateextra(
            ATCA_CONSTANTS.UPDATE_MODE_USER_EXTRA,
            config_data[84]
        )
        packets.append(packet)

        packet = self.atcab_updateextra(
            ATCA_CONSTANTS.UPDATE_MODE_SELECTOR,
            config_data[85]
        )
        packets.append(packet)

        return packets

    def atcab_write_enc(self, key_id, block, data, enc_key, enc_key_id):
        raise NotImplementedError("atcab_write_enc")

    def atcab_write_config_counter(self, counter_id, counter_value):
        raise NotImplementedError("atcab_write_config_counter")
