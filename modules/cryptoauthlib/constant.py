# -*- coding: utf-8 -*-
# pylint: disable=E0401
import sys
from micropython import const


class C(object):
    def __getattr__(self, a):
        if a == "ATCA_CMD_SIZE_MIN":
            return const(7)
        elif a == "ATCA_CMD_SIZE_MAX":
            return const(4 * 36 + 7)
        elif a == "CMD_STATUS_SUCCESS":
            return const(0x00)
        elif a == "CMD_STATUS_WAKEUP":
            return const(0x11)
        elif a == "CMD_STATUS_BYTE_PARSE":
            return const(0x03)
        elif a == "CMD_STATUS_BYTE_ECC":
            return const(0x05)
        elif a == "CMD_STATUS_BYTE_EXEC":
            return const(0x0F)
        elif a == "CMD_STATUS_BYTE_COMM":
            return const(0xFF)
        elif a == "ATCA_CHECKMAC":
            return const(0x28)
        elif a == "ATCA_DERIVE_KEY":
            return const(0x1C)
        elif a == "ATCA_INFO":
            return const(0x30)
        elif a == "ATCA_GENDIG":
            return const(0x15)
        elif a == "ATCA_GENKEY":
            return const(0x40)
        elif a == "ATCA_HMAC":
            return const(0x11)
        elif a == "ATCA_LOCK":
            return const(0x17)
        elif a == "ATCA_MAC":
            return const(0x08)
        elif a == "ATCA_NONCE":
            return const(0x16)
        elif a == "ATCA_PAUSE":
            return const(0x01)
        elif a == "ATCA_PRIVWRITE":
            return const(0x46)
        elif a == "ATCA_RANDOM":
            return const(0x1B)
        elif a == "ATCA_READ":
            return const(0x02)
        elif a == "ATCA_SIGN":
            return const(0x41)
        elif a == "ATCA_UPDATE_EXTRA":
            return const(0x20)
        elif a == "ATCA_VERIFY":
            return const(0x45)
        elif a == "ATCA_WRITE":
            return const(0x12)
        elif a == "ATCA_ECDH":
            return const(0x43)
        elif a == "ATCA_COUNTER":
            return const(0x24)
        elif a == "ATCA_SHA":
            return const(0x47)
        elif a == "ATCA_AES":
            return const(0x51)
        elif a == "ATCA_KDF":
            return const(0x56)
        elif a == "ATCA_SECUREBOOT":
            return const(0x80)
        elif a == "ATCA_SELFTEST":
            return const(0x77)
        elif a == "ATCA_KEY_SIZE":
            return const(32)
        elif a == "ATCA_BLOCK_SIZE":
            return const(32)
        elif a == "ATCA_WORD_SIZE":
            return const(4)
        elif a == "ATCA_PUB_KEY_PAD":
            return const(4)
        elif a == "ATCA_SERIAL_NUM_SIZE":
            return const(9)
        elif a == "ATCA_RSP_SIZE_VAL":
            return const(7)
        elif a == "ATCA_KEY_COUNT":
            return const(16)
        elif a == "ATCA_ECC_CONFIG_SIZE":
            return const(128)
        elif a == "ATCA_SHA_CONFIG_SIZE":
            return const(88)
        elif a == "ATCA_OTP_SIZE":
            return const(64)
        elif a == "ATCA_DATA_SIZE":
            return const(16 * 32)
        elif a == "ATCA_AES_GFM_SIZE":
            return const(32)
        elif a == "ATCA_CHIPMODE_OFFSET":
            return const(19)
        elif a == "ATCA_CHIPMODE_I2C_ADDRESS_FLAG":
            return const(0x01)
        elif a == "ATCA_CHIPMODE_TTL_ENABLE_FLAG":
            return const(0x02)
        elif a == "ATCA_CHIPMODE_WATCHDOG_MASK":
            return const(0x04)
        elif a == "ATCA_CHIPMODE_WATCHDOG_SHORT":
            return const(0x00)
        elif a == "ATCA_CHIPMODE_WATCHDOG_LONG":
            return const(0x04)
        elif a == "ATCA_CHIPMODE_CLOCK_DIV_MASK":
            return const(0xF8)
        elif a == "ATCA_CHIPMODE_CLOCK_DIV_M0":
            return const(0x00)
        elif a == "ATCA_CHIPMODE_CLOCK_DIV_M1":
            return const(0x28)
        elif a == "ATCA_CHIPMODE_CLOCK_DIV_M2":
            return const(0x68)
        elif a == "ATCA_COUNT_SIZE":
            return const(1)
        elif a == "ATCA_CRC_SIZE":
            return const(2)
        elif a == "ATCA_PACKET_OVERHEAD":
            return const(3)
        elif a == "ATCA_PUB_KEY_SIZE":
            return const(64)
        elif a == "ATCA_PRIV_KEY_SIZE":
            return const(32)
        elif a == "ATCA_SIG_SIZE":
            return const(64)
        elif a == "RSA2048_KEY_SIZE":
            return const(256)
        elif a == "ATCA_RSP_SIZE_MIN":
            return const(4)
        elif a == "ATCA_RSP_SIZE_4":
            return const(7)
        elif a == "ATCA_RSP_SIZE_72":
            return const(75)
        elif a == "ATCA_RSP_SIZE_64":
            return const(67)
        elif a == "ATCA_RSP_SIZE_32":
            return const(35)
        elif a == "ATCA_RSP_SIZE_16":
            return const(19)
        elif a == "ATCA_RSP_SIZE_MAX":
            return const(75)
        elif a == "OUTNONCE_SIZE":
            return const(32)
        elif a == "ATCA_KEY_ID_MAX":
            return const(15)
        elif a == "ATCA_OTP_BLOCK_MAX":
            return const(1)
        elif a == "ATCA_COUNT_IDX":
            return const(0)
        elif a == "ATCA_OPCODE_IDX":
            return const(1)
        elif a == "ATCA_PARAM1_IDX":
            return const(2)
        elif a == "ATCA_PARAM2_IDX":
            return const(3)
        elif a == "ATCA_DATA_IDX":
            return const(5)
        elif a == "ATCA_RSP_DATA_IDX":
            return const(1)
        elif a == "ATCA_ZONE_CONFIG":
            return const(0x00)
        elif a == "ATCA_ZONE_OTP":
            return const(0x01)
        elif a == "ATCA_ZONE_DATA":
            return const(0x02)
        elif a == "ATCA_ZONE_MASK":
            return const(0x03)
        elif a == "ATCA_ZONE_ENCRYPTED":
            return const(0x40)
        elif a == "ATCA_ZONE_READWRITE_32":
            return const(0x80)
        elif a == "ATCA_ADDRESS_MASK_CONFIG":
            return const(0x001F)
        elif a == "ATCA_ADDRESS_MASK_OTP":
            return const(0x000F)
        elif a == "ATCA_ADDRESS_MASK":
            return const(0x007F)
        elif a == "ATCA_TEMPKEY_KEYID":
            return const(0xFFFF)
        elif a == "ATCA_B283_KEY_TYPE":
            return const(0)
        elif a == "ATCA_K283_KEY_TYPE":
            return const(1)
        elif a == "ATCA_P256_KEY_TYPE":
            return const(4)
        elif a == "ATCA_AES_KEY_TYPE":
            return const(6)
        elif a == "ATCA_SHA_KEY_TYPE":
            return const(7)
        elif a == "AES_MODE_IDX":
            return const(2)
        elif a == "AES_KEYID_IDX":
            return const(3)
        elif a == "AES_INPUT_IDX":
            return const(5)
        elif a == "AES_COUNT":
            return const(23)
        elif a == "AES_MODE_MASK":
            return const(0xC7)
        elif a == "AES_MODE_KEY_BLOCK_MASK":
            return const(0xC0)
        elif a == "AES_MODE_OP_MASK":
            return const(0x07)
        elif a == "AES_MODE_ENCRYPT":
            return const(0x00)
        elif a == "AES_MODE_DECRYPT":
            return const(0x01)
        elif a == "AES_MODE_GFM":
            return const(0x03)
        elif a == "AES_MODE_KEY_BLOCK_POS":
            return const(6)
        elif a == "AES_DATA_SIZE":
            return const(16)
        elif a == "AES_RSP_SIZE":
            return const(19)
        elif a == "CHECKMAC_MODE_IDX":
            return const(2)
        elif a == "CHECKMAC_KEYID_IDX":
            return const(3)
        elif a == "CHECKMAC_CLIENT_CHALLENGE_IDX":
            return const(5)
        elif a == "CHECKMAC_CLIENT_RESPONSE_IDX":
            return const(37)
        elif a == "CHECKMAC_DATA_IDX":
            return const(69)
        elif a == "CHECKMAC_COUNT":
            return const(84)
        elif a == "CHECKMAC_MODE_CHALLENGE":
            return const(0x00)
        elif a == "CHECKMAC_MODE_BLOCK2_TEMPKEY":
            return const(0x01)
        elif a == "CHECKMAC_MODE_BLOCK1_TEMPKEY":
            return const(0x02)
        elif a == "CHECKMAC_MODE_SOURCE_FLAG_MATCH":
            return const(0x04)
        elif a == "CHECKMAC_MODE_INCLUDE_OTP_64":
            return const(0x20)
        elif a == "CHECKMAC_MODE_MASK":
            return const(0x27)
        elif a == "CHECKMAC_CLIENT_CHALLENGE_SIZE":
            return const(32)
        elif a == "CHECKMAC_CLIENT_RESPONSE_SIZE":
            return const(32)
        elif a == "CHECKMAC_OTHER_DATA_SIZE":
            return const(13)
        elif a == "CHECKMAC_CLIENT_COMMAND_SIZE":
            return const(4)
        elif a == "CHECKMAC_CMD_MATCH":
            return const(0)
        elif a == "CHECKMAC_CMD_MISMATCH":
            return const(1)
        elif a == "CHECKMAC_RSP_SIZE":
            return const(4)
        elif a == "COUNTER_COUNT":
            return const(7)
        elif a == "COUNTER_MODE_IDX":
            return const(2)
        elif a == "COUNTER_KEYID_IDX":
            return const(3)
        elif a == "COUNTER_MODE_MASK":
            return const(0x01)
        elif a == "COUNTER_MAX_VALUE":
            return const(2097151)
        elif a == "COUNTER_MODE_READ":
            return const(0x00)
        elif a == "COUNTER_MODE_INCREMENT":
            return const(0x01)
        elif a == "COUNTER_RSP_SIZE":
            return const(7)
        elif a == "DERIVE_KEY_RANDOM_IDX":
            return const(2)
        elif a == "DERIVE_KEY_TARGETKEY_IDX":
            return const(3)
        elif a == "DERIVE_KEY_MAC_IDX":
            return const(5)
        elif a == "DERIVE_KEY_COUNT_SMALL":
            return const(7)
        elif a == "DERIVE_KEY_MODE":
            return const(0x04)
        elif a == "DERIVE_KEY_COUNT_LARGE":
            return const(39)
        elif a == "DERIVE_KEY_RANDOM_FLAG":
            return const(4)
        elif a == "DERIVE_KEY_MAC_SIZE":
            return const(32)
        elif a == "DERIVE_KEY_RSP_SIZE":
            return const(4)
        elif a == "ECDH_PREFIX_MODE":
            return const(0x00)
        elif a == "ECDH_COUNT":
            return const(7 + 64)
        elif a == "ECDH_MODE_SOURCE_MASK":
            return const(0x01)
        elif a == "ECDH_MODE_SOURCE_EEPROM_SLOT":
            return const(0x00)
        elif a == "ECDH_MODE_SOURCE_TEMPKEY":
            return const(0x01)
        elif a == "ECDH_MODE_OUTPUT_MASK":
            return const(0x02)
        elif a == "ECDH_MODE_OUTPUT_CLEAR":
            return const(0x00)
        elif a == "ECDH_MODE_OUTPUT_ENC":
            return const(0x02)
        elif a == "ECDH_MODE_COPY_MASK":
            return const(0x0C)
        elif a == "ECDH_MODE_COPY_COMPATIBLE":
            return const(0x00)
        elif a == "ECDH_MODE_COPY_EEPROM_SLOT":
            return const(0x04)
        elif a == "ECDH_MODE_COPY_TEMP_KEY":
            return const(0x08)
        elif a == "ECDH_MODE_COPY_OUTPUT_BUFFER":
            return const(0x0C)
        elif a == "ECDH_KEY_SIZE":
            return const(32)
        elif a == "ECDH_RSP_SIZE":
            return const(67)
        elif a == "GENDIG_ZONE_IDX":
            return const(2)
        elif a == "GENDIG_KEYID_IDX":
            return const(3)
        elif a == "GENDIG_DATA_IDX":
            return const(5)
        elif a == "GENDIG_COUNT":
            return const(7)
        elif a == "GENDIG_ZONE_CONFIG":
            return const(0)
        elif a == "GENDIG_ZONE_OTP":
            return const(1)
        elif a == "GENDIG_ZONE_DATA":
            return const(2)
        elif a == "GENDIG_ZONE_SHARED_NONCE":
            return const(3)
        elif a == "GENDIG_ZONE_COUNTER":
            return const(4)
        elif a == "GENDIG_ZONE_KEY_CONFIG":
            return const(5)
        elif a == "GENDIG_RSP_SIZE":
            return const(4)
        elif a == "GENKEY_MODE_IDX":
            return const(2)
        elif a == "GENKEY_KEYID_IDX":
            return const(3)
        elif a == "GENKEY_DATA_IDX":
            return const(5)
        elif a == "GENKEY_COUNT":
            return const(7)
        elif a == "GENKEY_COUNT_DATA":
            return const(10)
        elif a == "GENKEY_OTHER_DATA_SIZE":
            return const(3)
        elif a == "GENKEY_MODE_MASK":
            return const(0x1C)
        elif a == "GENKEY_MODE_PRIVATE":
            return const(0x04)
        elif a == "GENKEY_MODE_PUBLIC":
            return const(0x00)
        elif a == "GENKEY_MODE_DIGEST":
            return const(0x08)
        elif a == "GENKEY_MODE_PUBKEY_DIGEST":
            return const(0x10)
        elif a == "GENKEY_PRIVATE_TO_TEMPKEY":
            return const(0xFFFF)
        elif a == "GENKEY_RSP_SIZE_SHORT":
            return const(4)
        elif a == "GENKEY_RSP_SIZE_LONG":
            return const(75)
        elif a == "HMAC_MODE_IDX":
            return const(2)
        elif a == "HMAC_KEYID_IDX":
            return const(3)
        elif a == "HMAC_COUNT":
            return const(7)
        elif a == "HMAC_MODE_FLAG_TK_RAND":
            return const(0x00)
        elif a == "HMAC_MODE_FLAG_TK_NORAND":
            return const(0x04)
        elif a == "HMAC_MODE_FLAG_OTP88":
            return const(0x10)
        elif a == "HMAC_MODE_FLAG_OTP64":
            return const(0x20)
        elif a == "HMAC_MODE_FLAG_FULLSN":
            return const(0x40)
        elif a == "HMAC_MODE_MASK":
            return const(0x74)
        elif a == "HMAC_DIGEST_SIZE":
            return const(32)
        elif a == "HMAC_RSP_SIZE":
            return const(35)
        elif a == "INFO_PARAM1_IDX":
            return const(2)
        elif a == "INFO_PARAM2_IDX":
            return const(3)
        elif a == "INFO_COUNT":
            return const(7)
        elif a == "INFO_MODE_REVISION":
            return const(0x00)
        elif a == "INFO_MODE_KEY_VALID":
            return const(0x01)
        elif a == "INFO_MODE_STATE":
            return const(0x02)
        elif a == "INFO_MODE_GPIO":
            return const(0x03)
        elif a == "INFO_MODE_VOL_KEY_PERMIT":
            return const(0x04)
        elif a == "INFO_MODE_MAX":
            return const(0x03)
        elif a == "INFO_NO_STATE":
            return const(0x00)
        elif a == "INFO_OUTPUT_STATE_MASK":
            return const(0x01)
        elif a == "INFO_DRIVER_STATE_MASK":
            return const(0x02)
        elif a == "INFO_PARAM2_SET_LATCH_STATE":
            return const(0x0002)
        elif a == "INFO_PARAM2_LATCH_SET":
            return const(0x0001)
        elif a == "INFO_PARAM2_LATCH_CLEAR":
            return const(0x0000)
        elif a == "INFO_SIZE":
            return const(0x04)
        elif a == "INFO_RSP_SIZE":
            return const(7)
        elif a == "KDF_MODE_IDX":
            return const(2)
        elif a == "KDF_KEYID_IDX":
            return const(3)
        elif a == "KDF_DETAILS_IDX":
            return const(5)
        elif a == "KDF_DETAILS_SIZE":
            return const(4)
        elif a == "KDF_MESSAGE_IDX":
            return const(5 + 4)
        elif a == "KDF_MODE_SOURCE_MASK":
            return const(0x03)
        elif a == "KDF_MODE_SOURCE_TEMPKEY":
            return const(0x00)
        elif a == "KDF_MODE_SOURCE_TEMPKEY_UP":
            return const(0x01)
        elif a == "KDF_MODE_SOURCE_SLOT":
            return const(0x02)
        elif a == "KDF_MODE_SOURCE_ALTKEYBUF":
            return const(0x03)
        elif a == "KDF_MODE_TARGET_MASK":
            return const(0x1C)
        elif a == "KDF_MODE_TARGET_TEMPKEY":
            return const(0x00)
        elif a == "KDF_MODE_TARGET_TEMPKEY_UP":
            return const(0x04)
        elif a == "KDF_MODE_TARGET_SLOT":
            return const(0x08)
        elif a == "KDF_MODE_TARGET_ALTKEYBUF":
            return const(0x0C)
        elif a == "KDF_MODE_TARGET_OUTPUT":
            return const(0x10)
        elif a == "KDF_MODE_TARGET_OUTPUT_ENC":
            return const(0x14)
        elif a == "KDF_MODE_ALG_MASK":
            return const(0x60)
        elif a == "KDF_MODE_ALG_PRF":
            return const(0x00)
        elif a == "KDF_MODE_ALG_AES":
            return const(0x20)
        elif a == "KDF_MODE_ALG_HKDF":
            return const(0x40)
        elif a == "KDF_DETAILS_PRF_KEY_LEN_MASK":
            return const(0x00000003)
        elif a == "KDF_DETAILS_PRF_KEY_LEN_16":
            return const(0x00000000)
        elif a == "KDF_DETAILS_PRF_KEY_LEN_32":
            return const(0x00000001)
        elif a == "KDF_DETAILS_PRF_KEY_LEN_48":
            return const(0x00000002)
        elif a == "KDF_DETAILS_PRF_KEY_LEN_64":
            return const(0x00000003)
        elif a == "KDF_DETAILS_PRF_TARGET_LEN_MASK":
            return const(0x00000100)
        elif a == "KDF_DETAILS_PRF_TARGET_LEN_32":
            return const(0x00000000)
        elif a == "KDF_DETAILS_PRF_TARGET_LEN_64":
            return const(0x00000100)
        elif a == "KDF_DETAILS_PRF_AEAD_MASK":
            return const(0x00000600)
        elif a == "KDF_DETAILS_PRF_AEAD_MODE0":
            return const(0x00000000)
        elif a == "KDF_DETAILS_PRF_AEAD_MODE1":
            return const(0x00000200)
        elif a == "KDF_DETAILS_AES_KEY_LOC_MASK":
            return const(0x00000003)
        elif a == "KDF_DETAILS_HKDF_MSG_LOC_MASK":
            return const(0x00000003)
        elif a == "KDF_DETAILS_HKDF_MSG_LOC_SLOT":
            return const(0x00000000)
        elif a == "KDF_DETAILS_HKDF_MSG_LOC_TEMPKEY":
            return const(0x00000001)
        elif a == "KDF_DETAILS_HKDF_MSG_LOC_INPUT":
            return const(0x00000002)
        elif a == "KDF_DETAILS_HKDF_MSG_LOC_IV":
            return const(0x00000003)
        elif a == "KDF_DETAILS_HKDF_ZERO_KEY":
            return const(0x00000004)
        elif a == "LOCK_ZONE_IDX":
            return const(2)
        elif a == "LOCK_SUMMARY_IDX":
            return const(3)
        elif a == "LOCK_COUNT":
            return const(7)
        elif a == "LOCK_ZONE_CONFIG":
            return const(0x00)
        elif a == "LOCK_ZONE_DATA":
            return const(0x01)
        elif a == "LOCK_ZONE_DATA_SLOT":
            return const(0x02)
        elif a == "LOCK_ZONE_NO_CRC":
            return const(0x80)
        elif a == "LOCK_ZONE_MASK":
            return const(0xBF)
        elif a == "ATCA_UNLOCKED":
            return const(0x55)
        elif a == "ATCA_LOCKED":
            return const(0x00)
        elif a == "LOCK_RSP_SIZE":
            return const(4)
        elif a == "MAC_MODE_IDX":
            return const(2)
        elif a == "MAC_KEYID_IDX":
            return const(3)
        elif a == "MAC_CHALLENGE_IDX":
            return const(5)
        elif a == "MAC_COUNT_SHORT":
            return const(7)
        elif a == "MAC_COUNT_LONG":
            return const(39)
        elif a == "MAC_MODE_CHALLENGE":
            return const(0x00)
        elif a == "MAC_MODE_BLOCK2_TEMPKEY":
            return const(0x01)
        elif a == "MAC_MODE_BLOCK1_TEMPKEY":
            return const(0x02)
        elif a == "MAC_MODE_SOURCE_FLAG_MATCH":
            return const(0x04)
        elif a == "MAC_MODE_PTNONCE_TEMPKEY":
            return const(0x06)
        elif a == "MAC_MODE_PASSTHROUGH":
            return const(0x07)
        elif a == "MAC_MODE_INCLUDE_OTP_88":
            return const(0x10)
        elif a == "MAC_MODE_INCLUDE_OTP_64":
            return const(0x20)
        elif a == "MAC_MODE_INCLUDE_SN":
            return const(0x40)
        elif a == "MAC_CHALLENGE_SIZE":
            return const(32)
        elif a == "MAC_SIZE":
            return const(32)
        elif a == "MAC_MODE_MASK":
            return const(0x77)
        elif a == "MAC_RSP_SIZE":
            return const(35)
        elif a == "NONCE_MODE_IDX":
            return const(2)
        elif a == "NONCE_PARAM2_IDX":
            return const(3)
        elif a == "NONCE_INPUT_IDX":
            return const(5)
        elif a == "NONCE_COUNT_SHORT":
            return const(7 + 20)
        elif a == "NONCE_COUNT_LONG":
            return const(7 + 32)
        elif a == "NONCE_COUNT_LONG_64":
            return const(7 + 64)
        elif a == "NONCE_MODE_MASK":
            return const(0x03)
        elif a == "NONCE_MODE_SEED_UPDATE":
            return const(0x00)
        elif a == "NONCE_MODE_NO_SEED_UPDATE":
            return const(0x01)
        elif a == "NONCE_MODE_INVALID":
            return const(0x02)
        elif a == "NONCE_MODE_PASSTHROUGH":
            return const(0x03)
        elif a == "NONCE_MODE_INPUT_LEN_MASK":
            return const(0x20)
        elif a == "NONCE_MODE_INPUT_LEN_32":
            return const(0x00)
        elif a == "NONCE_MODE_INPUT_LEN_64":
            return const(0x20)
        elif a == "NONCE_MODE_TARGET_MASK":
            return const(0xC0)
        elif a == "NONCE_MODE_TARGET_TEMPKEY":
            return const(0x00)
        elif a == "NONCE_MODE_TARGET_MSGDIGBUF":
            return const(0x40)
        elif a == "NONCE_MODE_TARGET_ALTKEYBUF":
            return const(0x80)
        elif a == "NONCE_ZERO_CALC_MASK":
            return const(0x8000)
        elif a == "NONCE_ZERO_CALC_RANDOM":
            return const(0x0000)
        elif a == "NONCE_ZERO_CALC_TEMPKEY":
            return const(0x8000)
        elif a == "NONCE_NUMIN_SIZE":
            return const(20)
        elif a == "NONCE_NUMIN_SIZE_PASSTHROUGH":
            return const(32)
        elif a == "NONCE_RSP_SIZE_SHORT":
            return const(4)
        elif a == "NONCE_RSP_SIZE_LONG":
            return const(35)
        elif a == "PAUSE_SELECT_IDX":
            return const(2)
        elif a == "PAUSE_PARAM2_IDX":
            return const(3)
        elif a == "PAUSE_COUNT":
            return const(7)
        elif a == "PAUSE_RSP_SIZE":
            return const(4)
        elif a == "PRIVWRITE_ZONE_IDX":
            return const(2)
        elif a == "PRIVWRITE_KEYID_IDX":
            return const(3)
        elif a == "PRIVWRITE_VALUE_IDX":
            return const(5)
        elif a == "PRIVWRITE_MAC_IDX":
            return const(41)
        elif a == "PRIVWRITE_COUNT":
            return const(75)
        elif a == "PRIVWRITE_ZONE_MASK":
            return const(0x40)
        elif a == "PRIVWRITE_MODE_ENCRYPT":
            return const(0x40)
        elif a == "PRIVWRITE_RSP_SIZE":
            return const(4)
        elif a == "RANDOM_MODE_IDX":
            return const(2)
        elif a == "RANDOM_PARAM2_IDX":
            return const(3)
        elif a == "RANDOM_COUNT":
            return const(7)
        elif a == "RANDOM_SEED_UPDATE":
            return const(0x00)
        elif a == "RANDOM_NO_SEED_UPDATE":
            return const(0x01)
        elif a == "RANDOM_NUM_SIZE":
            return const(32)
        elif a == "RANDOM_RSP_SIZE":
            return const(35)
        elif a == "READ_ZONE_IDX":
            return const(2)
        elif a == "READ_ADDR_IDX":
            return const(3)
        elif a == "READ_COUNT":
            return const(7)
        elif a == "READ_ZONE_MASK":
            return const(0x83)
        elif a == "READ_4_RSP_SIZE":
            return const(7)
        elif a == "READ_32_RSP_SIZE":
            return const(35)
        elif a == "SECUREBOOT_MODE_IDX":
            return const(2)
        elif a == "SECUREBOOT_DIGEST_SIZE":
            return const(32)
        elif a == "SECUREBOOT_SIGNATURE_SIZE":
            return const(64)
        elif a == "SECUREBOOT_COUNT_DIG":
            return const(7 + 32)
        elif a == "SECUREBOOT_COUNT_DIG_SIG":
            return const(7 + 32 + 64)
        elif a == "SECUREBOOT_MAC_SIZE":
            return const(32)
        elif a == "SECUREBOOT_RSP_SIZE_NO_MAC":
            return const(4)
        elif a == "SECUREBOOT_RSP_SIZE_MAC":
            return const(3 + 32)
        elif a == "SECUREBOOT_MODE_MASK":
            return const(0x07)
        elif a == "SECUREBOOT_MODE_FULL":
            return const(0x05)
        elif a == "SECUREBOOT_MODE_FULL_STORE":
            return const(0x06)
        elif a == "SECUREBOOT_MODE_FULL_COPY":
            return const(0x07)
        elif a == "SECUREBOOT_MODE_PROHIBIT_FLAG":
            return const(0x40)
        elif a == "SECUREBOOT_MODE_ENC_MAC_FLAG":
            return const(0x80)
        elif a == "SECUREBOOTCONFIG_OFFSET":
            return const(70)
        elif a == "SECUREBOOTCONFIG_MODE_MASK":
            return const(0x0003)
        elif a == "SECUREBOOTCONFIG_MODE_DISABLED":
            return const(0x0000)
        elif a == "SECUREBOOTCONFIG_MODE_FULL_BOTH":
            return const(0x0001)
        elif a == "SECUREBOOTCONFIG_MODE_FULL_SIG":
            return const(0x0002)
        elif a == "SECUREBOOTCONFIG_MODE_FULL_DIG":
            return const(0x0003)
        elif a == "SELFTEST_MODE_IDX":
            return const(2)
        elif a == "SELFTEST_COUNT":
            return const(7)
        elif a == "SELFTEST_MODE_RNG":
            return const(0x01)
        elif a == "SELFTEST_MODE_ECDSA_SIGN_VERIFY":
            return const(0x02)
        elif a == "SELFTEST_MODE_ECDH":
            return const(0x08)
        elif a == "SELFTEST_MODE_AES":
            return const(0x10)
        elif a == "SELFTEST_MODE_SHA":
            return const(0x20)
        elif a == "SELFTEST_MODE_ALL":
            return const(0x3B)
        elif a == "SELFTEST_RSP_SIZE":
            return const(4)
        elif a == "SHA_COUNT_SHORT":
            return const(7)
        elif a == "SHA_COUNT_LONG":
            return const(7)
        elif a == "ATCA_SHA_DIGEST_SIZE":
            return const(32)
        elif a == "SHA_DATA_MAX":
            return const(64)
        elif a == "ATCA_SHA256_BLOCK_SIZE":
            return const(64)
        elif a == "SHA_CONTEXT_MAX_SIZE":
            return const(99)
        elif a == "SHA_MODE_MASK":
            return const(0x07)
        elif a == "SHA_MODE_SHA256_START":
            return const(0x00)
        elif a == "SHA_MODE_SHA256_UPDATE":
            return const(0x01)
        elif a == "SHA_MODE_SHA256_END":
            return const(0x02)
        elif a == "SHA_MODE_SHA256_PUBLIC":
            return const(0x03)
        elif a == "SHA_MODE_HMAC_START":
            return const(0x04)
        elif a == "SHA_MODE_HMAC_UPDATE":
            return const(0x01)
        elif a == "SHA_MODE_HMAC_END":
            return const(0x05)
        elif a == "SHA_MODE_608_HMAC_END":
            return const(0x02)
        elif a == "SHA_MODE_READ_CONTEXT":
            return const(0x06)
        elif a == "SHA_MODE_WRITE_CONTEXT":
            return const(0x07)
        elif a == "SHA_MODE_TARGET_MASK":
            return const(0xC0)
        elif a == "SHA_MODE_TARGET_TEMPKEY":
            return const(0x00)
        elif a == "SHA_MODE_TARGET_MSGDIGBUF":
            return const(0x40)
        elif a == "SHA_MODE_TARGET_OUT_ONLY":
            return const(0xC0)
        elif a == "SHA_RSP_SIZE":
            return const(35)
        elif a == "SHA_RSP_SIZE_SHORT":
            return const(4)
        elif a == "SHA_RSP_SIZE_LONG":
            return const(35)
        elif a == "SIGN_MODE_IDX":
            return const(2)
        elif a == "SIGN_KEYID_IDX":
            return const(3)
        elif a == "SIGN_COUNT":
            return const(7)
        elif a == "SIGN_MODE_MASK":
            return const(0xE1)
        elif a == "SIGN_MODE_INTERNAL":
            return const(0x00)
        elif a == "SIGN_MODE_INVALIDATE":
            return const(0x01)
        elif a == "SIGN_MODE_INCLUDE_SN":
            return const(0x40)
        elif a == "SIGN_MODE_EXTERNAL":
            return const(0x80)
        elif a == "SIGN_MODE_SOURCE_MASK":
            return const(0x20)
        elif a == "SIGN_MODE_SOURCE_TEMPKEY":
            return const(0x00)
        elif a == "SIGN_MODE_SOURCE_MSGDIGBUF":
            return const(0x20)
        elif a == "SIGN_RSP_SIZE":
            return const(75)
        elif a == "UPDATE_MODE_IDX":
            return const(2)
        elif a == "UPDATE_VALUE_IDX":
            return const(3)
        elif a == "UPDATE_COUNT":
            return const(7)
        elif a == "UPDATE_MODE_USER_EXTRA":
            return const(0x00)
        elif a == "UPDATE_MODE_SELECTOR":
            return const(0x01)
        elif a == "UPDATE_MODE_USER_EXTRA_ADD":
            return const(0x01)
        elif a == "UPDATE_MODE_DEC_COUNTER":
            return const(0x02)
        elif a == "UPDATE_RSP_SIZE":
            return const(4)
        elif a == "VERIFY_MODE_IDX":
            return const(2)
        elif a == "VERIFY_KEYID_IDX":
            return const(3)
        elif a == "VERIFY_DATA_IDX":
            return const(5)
        elif a == "VERIFY_256_STORED_COUNT":
            return const(71)
        elif a == "VERIFY_283_STORED_COUNT":
            return const(79)
        elif a == "VERIFY_256_VALIDATE_COUNT":
            return const(90)
        elif a == "VERIFY_283_VALIDATE_COUNT":
            return const(98)
        elif a == "VERIFY_256_EXTERNAL_COUNT":
            return const(135)
        elif a == "VERIFY_283_EXTERNAL_COUNT":
            return const(151)
        elif a == "VERIFY_256_KEY_SIZE":
            return const(64)
        elif a == "VERIFY_283_KEY_SIZE":
            return const(72)
        elif a == "VERIFY_256_SIGNATURE_SIZE":
            return const(64)
        elif a == "VERIFY_283_SIGNATURE_SIZE":
            return const(72)
        elif a == "VERIFY_OTHER_DATA_SIZE":
            return const(19)
        elif a == "VERIFY_MODE_MASK":
            return const(0x03)
        elif a == "VERIFY_MODE_STORED":
            return const(0x00)
        elif a == "VERIFY_MODE_VALIDATE_EXTERNAL":
            return const(0x01)
        elif a == "VERIFY_MODE_EXTERNAL":
            return const(0x02)
        elif a == "VERIFY_MODE_VALIDATE":
            return const(0x03)
        elif a == "VERIFY_MODE_INVALIDATE":
            return const(0x07)
        elif a == "VERIFY_MODE_SOURCE_MASK":
            return const(0x20)
        elif a == "VERIFY_MODE_SOURCE_TEMPKEY":
            return const(0x00)
        elif a == "VERIFY_MODE_SOURCE_MSGDIGBUF":
            return const(0x20)
        elif a == "VERIFY_MODE_MAC_FLAG":
            return const(0x80)
        elif a == "VERIFY_KEY_B283":
            return const(0)
        elif a == "VERIFY_KEY_K283":
            return const(0x0001)
        elif a == "VERIFY_KEY_P256":
            return const(0x0004)
        elif a == "VERIFY_RSP_SIZE":
            return const(4)
        elif a == "VERIFY_RSP_SIZE_MAC":
            return const(35)
        elif a == "WRITE_ZONE_IDX":
            return const(2)
        elif a == "WRITE_ADDR_IDX":
            return const(3)
        elif a == "WRITE_VALUE_IDX":
            return const(5)
        elif a == "WRITE_MAC_VS_IDX":
            return const(9)
        elif a == "WRITE_MAC_VL_IDX":
            return const(37)
        elif a == "WRITE_MAC_SIZE":
            return const(32)
        elif a == "WRITE_ZONE_MASK":
            return const(0xC3)
        elif a == "WRITE_ZONE_WITH_MAC":
            return const(0x40)
        elif a == "WRITE_ZONE_OTP":
            return const(1)
        elif a == "WRITE_ZONE_DATA":
            return const(2)
        elif a == "WRITE_RSP_SIZE":
            return const(4)
        elif a == "ATECC508A_EXECUTION_TIME":
            return {
                self.ATCA_CHECKMAC: const(13),
                self.ATCA_COUNTER: const(20),
                self.ATCA_DERIVE_KEY: const(50),
                self.ATCA_ECDH: const(58),
                self.ATCA_GENDIG: const(11),
                self.ATCA_GENKEY: const(115),
                self.ATCA_HMAC: const(23),
                self.ATCA_INFO: const(2),
                self.ATCA_LOCK: const(32),
                self.ATCA_MAC: const(14),
                self.ATCA_NONCE: const(29),
                self.ATCA_PAUSE: const(3),
                self.ATCA_PRIVWRITE: const(48),
                self.ATCA_RANDOM: const(23),
                self.ATCA_READ: const(5),
                self.ATCA_SHA: const(9),
                self.ATCA_SIGN: const(60),
                self.ATCA_UPDATE_EXTRA: const(10),
                self.ATCA_VERIFY: const(72),
                self.ATCA_WRITE: const(26)
            }
        elif a == "ATECC608A_EXECUTION_TIME":
            return {
                self.ATCA_AES: const(27),
                self.ATCA_CHECKMAC: const(40),
                self.ATCA_COUNTER: const(25),
                self.ATCA_DERIVE_KEY: const(50),
                self.ATCA_ECDH: const(60),
                self.ATCA_GENDIG: const(25),
                self.ATCA_GENKEY: const(115),
                self.ATCA_INFO: const(5),
                self.ATCA_KDF: const(165),
                self.ATCA_LOCK: const(35),
                self.ATCA_MAC: const(55),
                self.ATCA_NONCE: const(20),
                self.ATCA_PRIVWRITE: const(50),
                self.ATCA_RANDOM: const(23),
                self.ATCA_READ: const(5),
                self.ATCA_SECUREBOOT: const(80),
                self.ATCA_SELFTEST: const(250),
                self.ATCA_SHA: const(36),
                self.ATCA_SIGN: const(115),
                self.ATCA_UPDATE_EXTRA: const(10),
                self.ATCA_VERIFY: const(105),
                self.ATCA_WRITE: const(45)
            }
        elif a == "EXECUTION_TIME":
            return {
                "ATECC508A": self.ATECC508A_EXECUTION_TIME,
                "ATECC608A": self.ATECC608A_EXECUTION_TIME
            }

sys.modules[__name__] = C()