# -*- coding: utf-8 -*-
# pylint: disable=E0401
from micropython import const


""" command definitions """
# minimum number of bytes in command (from count byte to second CRC byte)
ATCA_CMD_SIZE_MIN = const(7)
# maximum size of command packet (Verify)
ATCA_CMD_SIZE_MAX = const(4 * 36 + 7)
# status byte for success
CMD_STATUS_SUCCESS = const(0x00)
# status byte after wake-up
CMD_STATUS_WAKEUP = const(0x11)
# command parse error
CMD_STATUS_BYTE_PARSE = const(0x03)
# command ECC error
CMD_STATUS_BYTE_ECC = const(0x05)
# command execution error
CMD_STATUS_BYTE_EXEC = const(0x0F)
# communication error
CMD_STATUS_BYTE_COMM = const(0xFF)


""" name opcodes for ATATECC Commands """
# CheckMac command op-code
ATCA_CHECKMAC = const(0x28)
# DeriveKey command op-code
ATCA_DERIVE_KEY = const(0x1C)
# Info command op-code
ATCA_INFO = const(0x30)
# GenDig command op-code
ATCA_GENDIG = const(0x15)
# GenKey command op-code
ATCA_GENKEY = const(0x40)
# HMAC command op-code
ATCA_HMAC = const(0x11)
# Lock command op-code
ATCA_LOCK = const(0x17)
# MAC command op-code
ATCA_MAC = const(0x08)
# Nonce command op-code
ATCA_NONCE = const(0x16)
# Pause command op-code
ATCA_PAUSE = const(0x01)
# PrivWrite command op-code
ATCA_PRIVWRITE = const(0x46)
# Random command op-code
ATCA_RANDOM = const(0x1B)
# Read command op-code
ATCA_READ = const(0x02)
# Sign command op-code
ATCA_SIGN = const(0x41)
# UpdateExtra command op-code
ATCA_UPDATE_EXTRA = const(0x20)
# GenKey command op-code
ATCA_VERIFY = const(0x45)
# Write command op-code
ATCA_WRITE = const(0x12)
# ECDH command op-code
ATCA_ECDH = const(0x43)
# Counter command op-code
ATCA_COUNTER = const(0x24)
# SHA command op-code
ATCA_SHA = const(0x47)
# AES command op-code
ATCA_AES = const(0x51)
# KDF command op-code
ATCA_KDF = const(0x56)
# Secure Boot command op-code
ATCA_SECUREBOOT = const(0x80)
# Self test command op-code
ATCA_SELFTEST = const(0x77)


""" name Definitions of Data and Packet Sizes """
# size of a symmetric SHA key
ATCA_KEY_SIZE = const(32)
# size of a block
ATCA_BLOCK_SIZE = const(32)
# size of a word
ATCA_WORD_SIZE = const(4)
# size of the public key pad
ATCA_PUB_KEY_PAD = const(4)
# number of bytes in the device serial number
ATCA_SERIAL_NUM_SIZE = const(9)
# size of response packet containing four bytes of data
ATCA_RSP_SIZE_VAL = const(7)
# number of keys
ATCA_KEY_COUNT = const(16)
# size of configuration zone
ATCA_ECC_CONFIG_SIZE = const(128)
# size of configuration zone
ATCA_SHA_CONFIG_SIZE = const(88)
# size of OTP zone
ATCA_OTP_SIZE = const(64)
# size of data zone
ATCA_DATA_SIZE = const(ATCA_KEY_COUNT * ATCA_KEY_SIZE)
# size of GFM data
ATCA_AES_GFM_SIZE = const(ATCA_BLOCK_SIZE)

# ChipMode byte offset within the configuration zone
ATCA_CHIPMODE_OFFSET = const(19)
# ChipMode I2C Address in UserExtraAdd flag
ATCA_CHIPMODE_I2C_ADDRESS_FLAG = const(0x01)
# ChipMode TTLenable flag
ATCA_CHIPMODE_TTL_ENABLE_FLAG = const(0x02)
# ChipMode watchdog duration mask
ATCA_CHIPMODE_WATCHDOG_MASK = const(0x04)
# ChipMode short watchdog (~1.3s)
ATCA_CHIPMODE_WATCHDOG_SHORT = const(0x00)
# ChipMode long watchdog (~13s)
ATCA_CHIPMODE_WATCHDOG_LONG = const(0x04)
# ChipMode clock divider mask
ATCA_CHIPMODE_CLOCK_DIV_MASK = const(0xF8)
# ChipMode clock divider M0
ATCA_CHIPMODE_CLOCK_DIV_M0 = const(0x00)
# ChipMode clock divider M1
ATCA_CHIPMODE_CLOCK_DIV_M1 = const(0x28)
# ChipMode clock divider M2
ATCA_CHIPMODE_CLOCK_DIV_M2 = const(0x68)

# Number of bytes in the command packet Count
ATCA_COUNT_SIZE = const(1)
# Number of bytes in the command packet CRC
ATCA_CRC_SIZE = const(2)
# Number of bytes in the command packet
ATCA_PACKET_OVERHEAD = const(ATCA_COUNT_SIZE + ATCA_CRC_SIZE)

# size of a p256 public key
ATCA_PUB_KEY_SIZE = const(64)
# size of a p256 private key
ATCA_PRIV_KEY_SIZE = const(32)
# size of a p256 signature
ATCA_SIG_SIZE = const(64)
# size of a RSA private key
RSA2048_KEY_SIZE = const(256)

# minimum number of bytes in response
ATCA_RSP_SIZE_MIN = const(4)
# size of response packet containing 4 bytes data
ATCA_RSP_SIZE_4 = const(7)
# size of response packet containing 64 bytes data
ATCA_RSP_SIZE_72 = const(75)
# size of response packet containing 64 bytes data
ATCA_RSP_SIZE_64 = const(67)
# size of response packet containing 32 bytes data
ATCA_RSP_SIZE_32 = const(35)
# size of response packet containing 16 bytes data
ATCA_RSP_SIZE_16 = const(19)
# maximum size of response packet (GenKey and Verify command)
ATCA_RSP_SIZE_MAX = const(75)

# Size of the OutNonce response expected from several commands
OUTNONCE_SIZE = const(32)

""" name Definitions for Command Parameter Ranges """
# maximum value for key id
ATCA_KEY_ID_MAX = const(15)
# maximum value for OTP block
ATCA_OTP_BLOCK_MAX = const(1)

""" name Definitions for Indexes Common to All Commands """
# command packet index for count
ATCA_COUNT_IDX = const(0)
# command packet index for op-code
ATCA_OPCODE_IDX = const(1)
# command packet index for first parameter
ATCA_PARAM1_IDX = const(2)
# command packet index for second parameter
ATCA_PARAM2_IDX = const(3)
# command packet index for data load
ATCA_DATA_IDX = const(5)
# buffer index of data in response
ATCA_RSP_DATA_IDX = const(1)

""" name Definitions for Zone and Address Parameters """
# Configuration zone
ATCA_ZONE_CONFIG = const(0x00)
# OTP (One Time Programming) zone
ATCA_ZONE_OTP = const(0x01)
# Data zone
ATCA_ZONE_DATA = const(0x02)
# Zone mask
ATCA_ZONE_MASK = const(0x03)
# Zone bit 6 set: Write is encrypted with an unlocked data zone.
ATCA_ZONE_ENCRYPTED = const(0x40)
# Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
ATCA_ZONE_READWRITE_32 = const(0x80)
# Address bits 5 to 7 are 0 for Configuration zone.
ATCA_ADDRESS_MASK_CONFIG = const(0x001F)
# Address bits 4 to 7 are 0 for OTP zone.
ATCA_ADDRESS_MASK_OTP = const(0x000F)
# Address bit 7 to 15 are always 0.
ATCA_ADDRESS_MASK = const(0x007F)
# KeyID when referencing TempKey
ATCA_TEMPKEY_KEYID = const(0xFFFF)

""" name Definitions for Key types """
# B283 NIST ECC key
ATCA_B283_KEY_TYPE = const(0)
# K283 NIST ECC key
ATCA_K283_KEY_TYPE = const(1)
# P256 NIST ECC key
ATCA_P256_KEY_TYPE = const(4)
# AES-128 Key
ATCA_AES_KEY_TYPE = const(6)
# SHA key or other data
ATCA_SHA_KEY_TYPE = const(7)

""" name Definitions for the AES Command """
# AES command index for mode
AES_MODE_IDX = const(ATCA_PARAM1_IDX)
# AES command index for key id
AES_KEYID_IDX = const(ATCA_PARAM2_IDX)
# AES command index for input data
AES_INPUT_IDX = const(ATCA_DATA_IDX)
# AES command packet size
AES_COUNT = const(23)
# AES mode bits 3 to 5 are 0
AES_MODE_MASK = const(0xC7)
# AES mode mask for key block field
AES_MODE_KEY_BLOCK_MASK = const(0xC0)
# AES mode operation mask
AES_MODE_OP_MASK = const(0x07)
# AES mode: Encrypt
AES_MODE_ENCRYPT = const(0x00)
# AES mode: Decrypt
AES_MODE_DECRYPT = const(0x01)
# AES mode: GFM calculation
AES_MODE_GFM = const(0x03)
# Bit shift for key block in mode
AES_MODE_KEY_BLOCK_POS = const(6)
# size of AES encrypt/decrypt data
AES_DATA_SIZE = const(16)
# AES command response packet size
AES_RSP_SIZE = const(ATCA_RSP_SIZE_16)

""" name Definitions for the CheckMac Command """
# CheckMAC command index for mode
CHECKMAC_MODE_IDX = const(ATCA_PARAM1_IDX)
# CheckMAC command index for key identifier
CHECKMAC_KEYID_IDX = const(ATCA_PARAM2_IDX)
# CheckMAC command index for client challenge
CHECKMAC_CLIENT_CHALLENGE_IDX = const(ATCA_DATA_IDX)
# CheckMAC command index for client response
CHECKMAC_CLIENT_RESPONSE_IDX = const(37)
# CheckMAC command index for other data
CHECKMAC_DATA_IDX = const(69)
# CheckMAC command packet size
CHECKMAC_COUNT = const(84)
# CheckMAC mode	 0: first SHA block from key id
CHECKMAC_MODE_CHALLENGE = const(0x00)
# CheckMAC mode bit 0: second SHA block from TempKey
CHECKMAC_MODE_BLOCK2_TEMPKEY = const(0x01)
# CheckMAC mode bit 1: first SHA block from TempKey
CHECKMAC_MODE_BLOCK1_TEMPKEY = const(0x02)
# CheckMAC mode bit 2: match TempKey.SourceFlag
CHECKMAC_MODE_SOURCE_FLAG_MATCH = const(0x04)
# CheckMAC mode bit 5: include first 64 OTP bits
CHECKMAC_MODE_INCLUDE_OTP_64 = const(0x20)
# CheckMAC mode bits 3, 4, 6, and 7 are 0.
CHECKMAC_MODE_MASK = const(0x27)
# CheckMAC size of client challenge
CHECKMAC_CLIENT_CHALLENGE_SIZE = const(32)
# CheckMAC size of client response
CHECKMAC_CLIENT_RESPONSE_SIZE = const(32)
# CheckMAC size of "other data"
CHECKMAC_OTHER_DATA_SIZE = const(13)
# CheckMAC size of client command header size inside "other data"
CHECKMAC_CLIENT_COMMAND_SIZE = const(4)
# CheckMAC return value when there is a match
CHECKMAC_CMD_MATCH = const(0)
# CheckMAC return value when there is a mismatch
CHECKMAC_CMD_MISMATCH = const(1)
# CheckMAC response packet size
CHECKMAC_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the Counter command """
COUNTER_COUNT = const(ATCA_CMD_SIZE_MIN)
# Counter command index for mode
COUNTER_MODE_IDX = const(ATCA_PARAM1_IDX)
# Counter command index for key id
COUNTER_KEYID_IDX = const(ATCA_PARAM2_IDX)
# Counter mode bits 1 to 7 are 0
COUNTER_MODE_MASK = const(0x01)
# Counter maximum value of the counter
COUNTER_MAX_VALUE = const(2097151)
# Counter command mode for reading
COUNTER_MODE_READ = const(0x00)
# Counter command mode for incrementing
COUNTER_MODE_INCREMENT = const(0x01)
# Counter command response packet size
COUNTER_RSP_SIZE = const(ATCA_RSP_SIZE_4)


""" name Definitions for the DeriveKey Command """
# DeriveKey command index for random bit
DERIVE_KEY_RANDOM_IDX = const(ATCA_PARAM1_IDX)
# DeriveKey command index for target slot
DERIVE_KEY_TARGETKEY_IDX = const(ATCA_PARAM2_IDX)
# DeriveKey command index for optional MAC
DERIVE_KEY_MAC_IDX = const(ATCA_DATA_IDX)
# DeriveKey command packet size without MAC
DERIVE_KEY_COUNT_SMALL = const(ATCA_CMD_SIZE_MIN)
# DeriveKey command mode set to 4 as in datasheet
DERIVE_KEY_MODE = const(0x04)
# DeriveKey command packet size with MAC
DERIVE_KEY_COUNT_LARGE = const(39)
# DeriveKey 1. parameter; has to match TempKey.SourceFlag
DERIVE_KEY_RANDOM_FLAG = const(4)
# DeriveKey MAC size
DERIVE_KEY_MAC_SIZE = const(32)
# DeriveKey response packet size
DERIVE_KEY_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the ECDH Command """
ECDH_PREFIX_MODE = const(0x00)
ECDH_COUNT = const(ATCA_CMD_SIZE_MIN + ATCA_PUB_KEY_SIZE)
ECDH_MODE_SOURCE_MASK = const(0x01)
ECDH_MODE_SOURCE_EEPROM_SLOT = const(0x00)
ECDH_MODE_SOURCE_TEMPKEY = const(0x01)
ECDH_MODE_OUTPUT_MASK = const(0x02)
ECDH_MODE_OUTPUT_CLEAR = const(0x00)
ECDH_MODE_OUTPUT_ENC = const(0x02)
ECDH_MODE_COPY_MASK = const(0x0C)
ECDH_MODE_COPY_COMPATIBLE = const(0x00)
ECDH_MODE_COPY_EEPROM_SLOT = const(0x04)
ECDH_MODE_COPY_TEMP_KEY = const(0x08)
ECDH_MODE_COPY_OUTPUT_BUFFER = const(0x0C)
# ECDH output data size
ECDH_KEY_SIZE = const(ATCA_BLOCK_SIZE)
# ECDH command packet size
ECDH_RSP_SIZE = const(ATCA_RSP_SIZE_64)


""" name Definitions for the GenDig Command """
# GenDig command index for zone
GENDIG_ZONE_IDX = const(ATCA_PARAM1_IDX)
# GenDig command index for key id
GENDIG_KEYID_IDX = const(ATCA_PARAM2_IDX)
# GenDig command index for optional data
GENDIG_DATA_IDX = const(ATCA_DATA_IDX)
# GenDig command packet size without "other data"
GENDIG_COUNT = const(ATCA_CMD_SIZE_MIN)
# GenDig zone id config. Use KeyID to specify any of the four 256-bit blocks of the Configuration zone.
GENDIG_ZONE_CONFIG = const(0)
# GenDig zone id OTP. Use KeyID to specify either the first or second 256-bit block of the OTP zone.
GENDIG_ZONE_OTP = const(1)
# GenDig zone id data. Use KeyID to specify a slot in the Data zone or a transport key in the hardware array.
GENDIG_ZONE_DATA = const(2)
# GenDig zone id shared nonce. KeyID specifies the location of the input value in the message generation.
GENDIG_ZONE_SHARED_NONCE = const(3)
# GenDig zone id counter. KeyID specifies the monotonic counter ID to be included in the message generation.
GENDIG_ZONE_COUNTER = const(4)
# GenDig zone id key config. KeyID specifies the slot for which the configuration information is to be included in the message generation.
GENDIG_ZONE_KEY_CONFIG = const(5)
# GenDig command response packet size
GENDIG_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the GenKey Command """
# GenKey command index for mode
GENKEY_MODE_IDX = const(ATCA_PARAM1_IDX)
# GenKey command index for key id
GENKEY_KEYID_IDX = const(ATCA_PARAM2_IDX)
# GenKey command index for other data
GENKEY_DATA_IDX = const(5)
# GenKey command packet size without "other data"
GENKEY_COUNT = const(ATCA_CMD_SIZE_MIN)
# GenKey command packet size with "other data"
GENKEY_COUNT_DATA = const(10)
# GenKey size of "other data"
GENKEY_OTHER_DATA_SIZE = const(3)
# GenKey mode bits 0 to 1 and 5 to 7 are 0
GENKEY_MODE_MASK = const(0x1C)
# GenKey mode: private key generation
GENKEY_MODE_PRIVATE = const(0x04)
# GenKey mode: public key calculation
GENKEY_MODE_PUBLIC = const(0x00)
# GenKey mode: PubKey digest will be created after the public key is calculated
GENKEY_MODE_DIGEST = const(0x08)
# GenKey mode: Calculate PubKey digest on the public key in KeyId
GENKEY_MODE_PUBKEY_DIGEST = const(0x10)
# GenKey Create private key and store to tempkey (608 only)
GENKEY_PRIVATE_TO_TEMPKEY = const(0xFFFF)
# GenKey response packet size in Digest mode
GENKEY_RSP_SIZE_SHORT = const(ATCA_RSP_SIZE_MIN)
# GenKey response packet size when returning a public key
GENKEY_RSP_SIZE_LONG = const(ATCA_RSP_SIZE_72)


""" name Definitions for the HMAC Command """
# HMAC command index for mode
HMAC_MODE_IDX = const(ATCA_PARAM1_IDX)
# HMAC command index for key id
HMAC_KEYID_IDX = const(ATCA_PARAM2_IDX)
# HMAC command packet size
HMAC_COUNT = const(ATCA_CMD_SIZE_MIN)
# HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
HMAC_MODE_FLAG_TK_RAND = const(0x00)
# HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
HMAC_MODE_FLAG_TK_NORAND = const(0x04)
# HMAC mode bit 4: Include the first 88 OTP bits (OTP[0] through OTP[10]) in the message.; otherwise, the corresponding message bits are set to zero. Not applicable for ATECC508A.
HMAC_MODE_FLAG_OTP88 = const(0x10)
# HMAC mode bit 5: Include the first 64 OTP bits (OTP[0] through OTP[7]) in the message.; otherwise, the corresponding message bits are set to zero. If Mode[4] is set, the value of this mode bit is ignored. Not applicable for ATECC508A.
HMAC_MODE_FLAG_OTP64 = const(0x20)
# HMAC mode bit 6: If set, include the 48 bits SN[2:3] and SN[4:7] in the message.; otherwise, the corresponding message bits are set to zero.
HMAC_MODE_FLAG_FULLSN = const(0x40)
# HMAC mode bits 0, 1, 3, and 7 are 0.
HMAC_MODE_MASK = const(0x74)
# HMAC size of digest response
HMAC_DIGEST_SIZE = const(32)
# HMAC command response packet size
HMAC_RSP_SIZE = const(ATCA_RSP_SIZE_32)


""" name Definitions for the Info Command """
# Info command index for 1. parameter
INFO_PARAM1_IDX = const(ATCA_PARAM1_IDX)
# Info command index for 2. parameter
INFO_PARAM2_IDX = const(ATCA_PARAM2_IDX)
# Info command packet size
INFO_COUNT = const(ATCA_CMD_SIZE_MIN)
# Info mode Revision
INFO_MODE_REVISION = const(0x00)
# Info mode KeyValid
INFO_MODE_KEY_VALID = const(0x01)
# Info mode State
INFO_MODE_STATE = const(0x02)
# Info mode GPIO
INFO_MODE_GPIO = const(0x03)
# Info mode GPIO
INFO_MODE_VOL_KEY_PERMIT = const(0x04)
# Info mode maximum value
INFO_MODE_MAX = const(0x03)
# Info mode is not the state mode.
INFO_NO_STATE = const(0x00)
# Info output state mask
INFO_OUTPUT_STATE_MASK = const(0x01)
# Info driver state mask
INFO_DRIVER_STATE_MASK = const(0x02)
# Info param2 to set the persistent latch state.
INFO_PARAM2_SET_LATCH_STATE = const(0x0002)
# Info param2 to set the persistent latch
INFO_PARAM2_LATCH_SET = const(0x0001)
# Info param2 to clear the persistent latch
INFO_PARAM2_LATCH_CLEAR = const(0x0000)
# Info return size
INFO_SIZE = const(0x04)
# Info command response packet size
INFO_RSP_SIZE = const(ATCA_RSP_SIZE_VAL)


""" name Definitions for the KDF Command """
# KDF command index for mode
KDF_MODE_IDX = const(ATCA_PARAM1_IDX)
# KDF command index for key id
KDF_KEYID_IDX = const(ATCA_PARAM2_IDX)
# KDF command index for details
KDF_DETAILS_IDX = const(ATCA_DATA_IDX)
# KDF details (param3) size
KDF_DETAILS_SIZE = const(4)
KDF_MESSAGE_IDX = const(ATCA_DATA_IDX + KDF_DETAILS_SIZE)

# KDF mode source key mask
KDF_MODE_SOURCE_MASK = const(0x03)
# KDF mode source key in TempKey
KDF_MODE_SOURCE_TEMPKEY = const(0x00)
# KDF mode source key in upper TempKey
KDF_MODE_SOURCE_TEMPKEY_UP = const(0x01)
# KDF mode source key in a slot
KDF_MODE_SOURCE_SLOT = const(0x02)
# KDF mode source key in alternate key buffer
KDF_MODE_SOURCE_ALTKEYBUF = const(0x03)

# KDF mode target key mask
KDF_MODE_TARGET_MASK = const(0x1C)
# KDF mode target key in TempKey
KDF_MODE_TARGET_TEMPKEY = const(0x00)
# KDF mode target key in upper TempKey
KDF_MODE_TARGET_TEMPKEY_UP = const(0x04)
# KDF mode target key in slot
KDF_MODE_TARGET_SLOT = const(0x08)
# KDF mode target key in alternate key buffer
KDF_MODE_TARGET_ALTKEYBUF = const(0x0C)
# KDF mode target key in output buffer
KDF_MODE_TARGET_OUTPUT = const(0x10)
# KDF mode target key encrypted in output buffer
KDF_MODE_TARGET_OUTPUT_ENC = const(0x14)

# KDF mode algorithm mask
KDF_MODE_ALG_MASK = const(0x60)
# KDF mode PRF algorithm
KDF_MODE_ALG_PRF = const(0x00)
# KDF mode AES algorithm
KDF_MODE_ALG_AES = const(0x20)
# KDF mode HKDF algorithm
KDF_MODE_ALG_HKDF = const(0x40)

# KDF details for PRF, source key length mask
KDF_DETAILS_PRF_KEY_LEN_MASK = const(0x00000003)
# KDF details for PRF, source key length is 16 bytes
KDF_DETAILS_PRF_KEY_LEN_16 = const(0x00000000)
# KDF details for PRF, source key length is 32 bytes
KDF_DETAILS_PRF_KEY_LEN_32 = const(0x00000001)
# KDF details for PRF, source key length is 48 bytes
KDF_DETAILS_PRF_KEY_LEN_48 = const(0x00000002)
# KDF details for PRF, source key length is 64 bytes
KDF_DETAILS_PRF_KEY_LEN_64 = const(0x00000003)

# KDF details for PRF, target length mask
KDF_DETAILS_PRF_TARGET_LEN_MASK = const(0x00000100)
# KDF details for PRF, target length is 32 bytes
KDF_DETAILS_PRF_TARGET_LEN_32 = const(0x00000000)
# KDF details for PRF, target length is 64 bytes
KDF_DETAILS_PRF_TARGET_LEN_64 = const(0x00000100)

# KDF details for PRF, AEAD processing mask
KDF_DETAILS_PRF_AEAD_MASK = const(0x00000600)
# KDF details for PRF, AEAD no processing
KDF_DETAILS_PRF_AEAD_MODE0 = const(0x00000000)
# KDF details for PRF, AEAD First 32 go to target, second 32 go to output buffer
KDF_DETAILS_PRF_AEAD_MODE1 = const(0x00000200)

# KDF details for AES, key location mask
KDF_DETAILS_AES_KEY_LOC_MASK = const(0x00000003)

# KDF details for HKDF, message location mask
KDF_DETAILS_HKDF_MSG_LOC_MASK = const(0x00000003)
# KDF details for HKDF, message location in slot
KDF_DETAILS_HKDF_MSG_LOC_SLOT = const(0x00000000)
# KDF details for HKDF, message location in TempKey
KDF_DETAILS_HKDF_MSG_LOC_TEMPKEY = const(0x00000001)
# KDF details for HKDF, message location in input parameter
KDF_DETAILS_HKDF_MSG_LOC_INPUT = const(0x00000002)
# KDF details for HKDF, message location is a special IV function
KDF_DETAILS_HKDF_MSG_LOC_IV = const(0x00000003)
# KDF details for HKDF, key is 32 bytes of zero
KDF_DETAILS_HKDF_ZERO_KEY = const(0x00000004)


""" name Definitions for the Lock Command """
# Lock command index for zone
LOCK_ZONE_IDX = const(ATCA_PARAM1_IDX)
# Lock command index for summary
LOCK_SUMMARY_IDX = const(ATCA_PARAM2_IDX)
# Lock command packet size
LOCK_COUNT = const(ATCA_CMD_SIZE_MIN)
# Lock zone is Config
LOCK_ZONE_CONFIG = const(0x00)
# Lock zone is OTP or Data
LOCK_ZONE_DATA = const(0x01)
# Lock slot of Data
LOCK_ZONE_DATA_SLOT = const(0x02)
# Lock command: Ignore summary.
LOCK_ZONE_NO_CRC = const(0x80)
# Lock parameter 1 bits 6 are 0.
LOCK_ZONE_MASK = const(0xBF)
# Value indicating an unlocked zone
ATCA_UNLOCKED = const(0x55)
# Value indicating a locked zone
ATCA_LOCKED = const(0x00)
# Lock command response packet size
LOCK_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the MAC Command """
# MAC command index for mode
MAC_MODE_IDX = const(ATCA_PARAM1_IDX)
# MAC command index for key id
MAC_KEYID_IDX = const(ATCA_PARAM2_IDX)
# MAC command index for optional challenge
MAC_CHALLENGE_IDX = const(ATCA_DATA_IDX)
# MAC command packet size without challenge
MAC_COUNT_SHORT = const(ATCA_CMD_SIZE_MIN)
# MAC command packet size with challenge
MAC_COUNT_LONG = const(39)
# MAC mode 0: first SHA block from data slot
MAC_MODE_CHALLENGE = const(0x00)
# MAC mode bit 0: second SHA block from TempKey
MAC_MODE_BLOCK2_TEMPKEY = const(0x01)
# MAC mode bit 1: first SHA block from TempKey
MAC_MODE_BLOCK1_TEMPKEY = const(0x02)
# MAC mode bit 2: match TempKey.SourceFlag
MAC_MODE_SOURCE_FLAG_MATCH = const(0x04)
# MAC mode bit 0: second SHA block from TempKey
MAC_MODE_PTNONCE_TEMPKEY = const(0x06)
# MAC mode bit 0-2: pass-through mode
MAC_MODE_PASSTHROUGH = const(0x07)
# MAC mode bit 4: include first 88 OTP bits
MAC_MODE_INCLUDE_OTP_88 = const(0x10)
# MAC mode bit 5: include first 64 OTP bits
MAC_MODE_INCLUDE_OTP_64 = const(0x20)
# MAC mode bit 6: include serial number
MAC_MODE_INCLUDE_SN = const(0x40)
# MAC size of challenge
MAC_CHALLENGE_SIZE = const(32)
# MAC size of response
MAC_SIZE = const(32)
# MAC mode bits 3 and 7 are 0.
MAC_MODE_MASK = const(0x77)
# MAC command response packet size
MAC_RSP_SIZE = const(ATCA_RSP_SIZE_32)


""" name Definitions for the Nonce Command """
# Nonce command index for mode
NONCE_MODE_IDX = const(ATCA_PARAM1_IDX)
# Nonce command index for 2. parameter
NONCE_PARAM2_IDX = const(ATCA_PARAM2_IDX)
# Nonce command index for input data
NONCE_INPUT_IDX = const(ATCA_DATA_IDX)
# Nonce command packet size for 20 bytes of NumIn
NONCE_COUNT_SHORT = const(ATCA_CMD_SIZE_MIN + 20)
# Nonce command packet size for 32 bytes of NumIn
NONCE_COUNT_LONG = const(ATCA_CMD_SIZE_MIN + 32)
# Nonce command packet size for 64 bytes of NumIn
NONCE_COUNT_LONG_64 = const(ATCA_CMD_SIZE_MIN + 64)
# Nonce mode bits 2 to 7 are 0.
NONCE_MODE_MASK = const(0x03)
# Nonce mode: update seed
NONCE_MODE_SEED_UPDATE = const(0x00)
# Nonce mode: do not update seed
NONCE_MODE_NO_SEED_UPDATE = const(0x01)
# Nonce mode 2 is invalid.
NONCE_MODE_INVALID = const(0x02)
# Nonce mode: pass-through
NONCE_MODE_PASSTHROUGH = const(0x03)

# Nonce mode: input size mask
NONCE_MODE_INPUT_LEN_MASK = const(0x20)
# Nonce mode: input size is 32 bytes
NONCE_MODE_INPUT_LEN_32 = const(0x00)
# Nonce mode: input size is 64 bytes
NONCE_MODE_INPUT_LEN_64 = const(0x20)

# Nonce mode: target mask
NONCE_MODE_TARGET_MASK = const(0xC0)
# Nonce mode: target is TempKey
NONCE_MODE_TARGET_TEMPKEY = const(0x00)
# Nonce mode: target is Message Digest Buffer
NONCE_MODE_TARGET_MSGDIGBUF = const(0x40)
# Nonce mode: target is Alternate Key Buffer
NONCE_MODE_TARGET_ALTKEYBUF = const(0x80)

# Nonce zero (param2): calculation mode mask
NONCE_ZERO_CALC_MASK = const(0x8000)
# Nonce zero (param2): calculation mode random, use RNG in calculation and return RNG output
NONCE_ZERO_CALC_RANDOM = const(0x0000)
# Nonce zero (param2): calculation mode TempKey, use TempKey in calculation and return new TempKey value
NONCE_ZERO_CALC_TEMPKEY = const(0x8000)

# Nonce NumIn size for random modes
NONCE_NUMIN_SIZE = const(20)
# Nonce NumIn size for 32-byte pass-through mode
NONCE_NUMIN_SIZE_PASSTHROUGH = const(32)

# Nonce command response packet size with no output
NONCE_RSP_SIZE_SHORT = const(ATCA_RSP_SIZE_MIN)
# Nonce command response packet size with output
NONCE_RSP_SIZE_LONG = const(ATCA_RSP_SIZE_32)


""" name Definitions for the Pause Command """
# Pause command index for Selector
PAUSE_SELECT_IDX = const(ATCA_PARAM1_IDX)
# Pause command index for 2. parameter
PAUSE_PARAM2_IDX = const(ATCA_PARAM2_IDX)
# Pause command packet size
PAUSE_COUNT = const(ATCA_CMD_SIZE_MIN)
# Pause command response packet size
PAUSE_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the PrivWrite Command """
# PrivWrite command index for zone
PRIVWRITE_ZONE_IDX = const(ATCA_PARAM1_IDX)
# PrivWrite command index for KeyID
PRIVWRITE_KEYID_IDX = const(ATCA_PARAM2_IDX)
# PrivWrite command index for value
PRIVWRITE_VALUE_IDX = const(5)
# PrivWrite command index for MAC
PRIVWRITE_MAC_IDX = const(41)
# PrivWrite command packet size
PRIVWRITE_COUNT = const(75)
# PrivWrite zone bits 0 to 5 and 7 are 0.
PRIVWRITE_ZONE_MASK = const(0x40)
# PrivWrite mode: encrypted
PRIVWRITE_MODE_ENCRYPT = const(0x40)
# PrivWrite command response packet size
PRIVWRITE_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the Random Command """
# Random command index for mode
RANDOM_MODE_IDX = const(ATCA_PARAM1_IDX)
# Random command index for 2. parameter
RANDOM_PARAM2_IDX = const(ATCA_PARAM2_IDX)
# Random command packet size
RANDOM_COUNT = const(ATCA_CMD_SIZE_MIN)
# Random mode for automatic seed update
RANDOM_SEED_UPDATE = const(0x00)
# Random mode for no seed update
RANDOM_NO_SEED_UPDATE = const(0x01)
# Number of bytes in the data packet of a random command
RANDOM_NUM_SIZE = const(32)
# Random command response packet size
RANDOM_RSP_SIZE = const(ATCA_RSP_SIZE_32)


""" name Definitions for the Read Command """
# Read command index for zone
READ_ZONE_IDX = const(ATCA_PARAM1_IDX)
# Read command index for address
READ_ADDR_IDX = const(ATCA_PARAM2_IDX)
# Read command packet size
READ_COUNT = const(ATCA_CMD_SIZE_MIN)
# Read zone bits 2 to 6 are 0.
READ_ZONE_MASK = const(0x83)
# Read command response packet size when reading 4 bytes
READ_4_RSP_SIZE = const(ATCA_RSP_SIZE_VAL)
# Read command response packet size when reading 32 bytes
READ_32_RSP_SIZE = const(ATCA_RSP_SIZE_32)


""" name Definitions for the SecureBoot Command """
# SecureBoot command index for mode
SECUREBOOT_MODE_IDX = const(ATCA_PARAM1_IDX)
# SecureBoot digest input size
SECUREBOOT_DIGEST_SIZE = const(32)
# SecureBoot signature input size
SECUREBOOT_SIGNATURE_SIZE = const(64)
# SecureBoot command packet size for just a digest
SECUREBOOT_COUNT_DIG = const(ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE)
# SecureBoot command packet size for a digest and signature
SECUREBOOT_COUNT_DIG_SIG = const(
    ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE)
# SecureBoot MAC output size
SECUREBOOT_MAC_SIZE = const(32)
# SecureBoot response packet size for no MAC
SECUREBOOT_RSP_SIZE_NO_MAC = const(ATCA_RSP_SIZE_MIN)
# SecureBoot response packet size with MAC
SECUREBOOT_RSP_SIZE_MAC = const(ATCA_PACKET_OVERHEAD + SECUREBOOT_MAC_SIZE)

# SecureBoot mode mask
SECUREBOOT_MODE_MASK = const(0x07)
# SecureBoot mode Full
SECUREBOOT_MODE_FULL = const(0x05)
# SecureBoot mode FullStore
SECUREBOOT_MODE_FULL_STORE = const(0x06)
# SecureBoot mode FullCopy
SECUREBOOT_MODE_FULL_COPY = const(0x07)
# SecureBoot mode flag to prohibit SecureBoot until next power cycle
SECUREBOOT_MODE_PROHIBIT_FLAG = const(0x40)
# SecureBoot mode flag for encrypted digest and returning validating MAC
SECUREBOOT_MODE_ENC_MAC_FLAG = const(0x80)

# SecureBootConfig byte offset into the configuration zone
SECUREBOOTCONFIG_OFFSET = const(70)
# Mask for SecureBootMode field in SecureBootConfig value
SECUREBOOTCONFIG_MODE_MASK = const(0x0003)
# Disabled SecureBootMode in SecureBootConfig value
SECUREBOOTCONFIG_MODE_DISABLED = const(0x0000)
# Both digest and signature always required SecureBootMode in SecureBootConfig value
SECUREBOOTCONFIG_MODE_FULL_BOTH = const(0x0001)
# Signature stored SecureBootMode in SecureBootConfig value
SECUREBOOTCONFIG_MODE_FULL_SIG = const(0x0002)
# Digest stored SecureBootMode in SecureBootConfig value
SECUREBOOTCONFIG_MODE_FULL_DIG = const(0x0003)


""" name Definitions for the SelfTest Command """
# SelfTest command index for mode
SELFTEST_MODE_IDX = const(ATCA_PARAM1_IDX)
# SelfTest command packet size
SELFTEST_COUNT = const(ATCA_CMD_SIZE_MIN)
# SelfTest mode RNG DRBG function
SELFTEST_MODE_RNG = const(0x01)
# SelfTest mode ECDSA verify function
SELFTEST_MODE_ECDSA_SIGN_VERIFY = const(0x02)
# SelfTest mode ECDH function
SELFTEST_MODE_ECDH = const(0x08)
# SelfTest mode AES encrypt function
SELFTEST_MODE_AES = const(0x10)
# SelfTest mode SHA function
SELFTEST_MODE_SHA = const(0x20)
# SelfTest mode all algorithms
SELFTEST_MODE_ALL = const(0x3B)
# SelfTest command response packet size
SELFTEST_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the SHA Command """
SHA_COUNT_SHORT = const(ATCA_CMD_SIZE_MIN)
# Just a starting size
SHA_COUNT_LONG = const(ATCA_CMD_SIZE_MIN)
ATCA_SHA_DIGEST_SIZE = const(32)
SHA_DATA_MAX = const(64)
ATCA_SHA256_BLOCK_SIZE = const(64)
SHA_CONTEXT_MAX_SIZE = const(99)

# Mask the bit 0-2
SHA_MODE_MASK = const(0x07)
# Initialization, does not accept a message
SHA_MODE_SHA256_START = const(0x00)
# Add 64 bytes in the meesage to the SHA context
SHA_MODE_SHA256_UPDATE = const(0x01)
# Complete the calculation and return the digest
SHA_MODE_SHA256_END = const(0x02)
# Add 64 byte ECC public key in the slot to the SHA context
SHA_MODE_SHA256_PUBLIC = const(0x03)
# Initialization, HMAC calculation
SHA_MODE_HMAC_START = const(0x04)
# Add 64 bytes in the meesage to the SHA context
SHA_MODE_HMAC_UPDATE = const(0x01)
# Complete the HMAC computation and return digest
SHA_MODE_HMAC_END = const(0x05)
# Complete the HMAC computation and return digest... Different command on 608
SHA_MODE_608_HMAC_END = const(0x02)
# Read current SHA-256 context out of the device
SHA_MODE_READ_CONTEXT = const(0x06)
# Restore a SHA-256 context into the device
SHA_MODE_WRITE_CONTEXT = const(0x07)
# Resulting digest target location mask
SHA_MODE_TARGET_MASK = const(0xC0)
# Place resulting digest both in Output buffer and TempKey
SHA_MODE_TARGET_TEMPKEY = const(0x00)
# Place resulting digest both in Output buffer and Message Digest Buffer
SHA_MODE_TARGET_MSGDIGBUF = const(0x40)
# Place resulting digest both in Output buffer ONLY
SHA_MODE_TARGET_OUT_ONLY = const(0xC0)

# SHA command response packet size
SHA_RSP_SIZE = const(ATCA_RSP_SIZE_32)
# SHA command response packet size only status code
SHA_RSP_SIZE_SHORT = const(ATCA_RSP_SIZE_MIN)
# SHA command response packet size
SHA_RSP_SIZE_LONG = const(ATCA_RSP_SIZE_32)


""" name Definitions for the Sign Command """
# Sign command index for mode
SIGN_MODE_IDX = const(ATCA_PARAM1_IDX)
# Sign command index for key id
SIGN_KEYID_IDX = const(ATCA_PARAM2_IDX)
# Sign command packet size
SIGN_COUNT = const(ATCA_CMD_SIZE_MIN)
# Sign mode bits 1 to 4 are 0
SIGN_MODE_MASK = const(0xE1)
# Sign mode	 0: internal
SIGN_MODE_INTERNAL = const(0x00)
# Sign mode bit 1: Signature will be used for Verify(Invalidate)
SIGN_MODE_INVALIDATE = const(0x01)
# Sign mode bit 6: include serial number
SIGN_MODE_INCLUDE_SN = const(0x40)
# Sign mode bit 7: external
SIGN_MODE_EXTERNAL = const(0x80)
# Sign mode message source mask
SIGN_MODE_SOURCE_MASK = const(0x20)
# Sign mode message source is TempKey
SIGN_MODE_SOURCE_TEMPKEY = const(0x00)
# Sign mode message source is the Message Digest Buffer
SIGN_MODE_SOURCE_MSGDIGBUF = const(0x20)
# Sign command response packet size
SIGN_RSP_SIZE = const(ATCA_RSP_SIZE_MAX)

""" name Definitions for the UpdateExtra Command """
# UpdateExtra command index for mode
UPDATE_MODE_IDX = const(ATCA_PARAM1_IDX)
# UpdateExtra command index for new value
UPDATE_VALUE_IDX = const(ATCA_PARAM2_IDX)
# UpdateExtra command packet size
UPDATE_COUNT = const(ATCA_CMD_SIZE_MIN)
# UpdateExtra mode update UserExtra (config byte 84)
UPDATE_MODE_USER_EXTRA = const(0x00)
# UpdateExtra mode update Selector (config byte 85)
UPDATE_MODE_SELECTOR = const(0x01)
# UpdateExtra mode update UserExtraAdd (config byte 85)
UPDATE_MODE_USER_EXTRA_ADD = const(UPDATE_MODE_SELECTOR)
# UpdateExtra mode: decrement counter
UPDATE_MODE_DEC_COUNTER = const(0x02)
# UpdateExtra command response packet size
UPDATE_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" name Definitions for the Verify Command """
# Verify command index for mode
VERIFY_MODE_IDX = const(ATCA_PARAM1_IDX)
# Verify command index for key id
VERIFY_KEYID_IDX = const(ATCA_PARAM2_IDX)
# Verify command index for data
VERIFY_DATA_IDX = const(5)
# Verify command packet size for 256-bit key in stored mode
VERIFY_256_STORED_COUNT = const(71)
# Verify command packet size for 283-bit key in stored mode
VERIFY_283_STORED_COUNT = const(79)
# Verify command packet size for 256-bit key in validate mode
VERIFY_256_VALIDATE_COUNT = const(90)
# Verify command packet size for 283-bit key in validate mode
VERIFY_283_VALIDATE_COUNT = const(98)
# Verify command packet size for 256-bit key in external mode
VERIFY_256_EXTERNAL_COUNT = const(135)
# Verify command packet size for 283-bit key in external mode
VERIFY_283_EXTERNAL_COUNT = const(151)
# Verify key size for 256-bit key
VERIFY_256_KEY_SIZE = const(64)
# Verify key size for 283-bit key
VERIFY_283_KEY_SIZE = const(72)
# Verify signature size for 256-bit key
VERIFY_256_SIGNATURE_SIZE = const(64)
# Verify signature size for 283-bit key
VERIFY_283_SIGNATURE_SIZE = const(72)
# Verify size of "other data"
VERIFY_OTHER_DATA_SIZE = const(19)
# Verify mode bits 2 to 7 are 0
VERIFY_MODE_MASK = const(0x03)
# Verify mode: stored
VERIFY_MODE_STORED = const(0x00)
# Verify mode: validate external
VERIFY_MODE_VALIDATE_EXTERNAL = const(0x01)
# Verify mode: external
VERIFY_MODE_EXTERNAL = const(0x02)
# Verify mode: validate
VERIFY_MODE_VALIDATE = const(0x03)
# Verify mode: invalidate
VERIFY_MODE_INVALIDATE = const(0x07)
# Verify mode message source mask
VERIFY_MODE_SOURCE_MASK = const(0x20)
# Verify mode message source is TempKey
VERIFY_MODE_SOURCE_TEMPKEY = const(0x00)
# Verify mode message source is the Message Digest Buffer
VERIFY_MODE_SOURCE_MSGDIGBUF = const(0x20)
# Verify mode: MAC
VERIFY_MODE_MAC_FLAG = const(0x80)
# Verify key type: B283
VERIFY_KEY_B283 = const(0)
# Verify key type: K283
VERIFY_KEY_K283 = const(0x0001)
# Verify key type: P256
VERIFY_KEY_P256 = const(0x0004)
# Verify command response packet size
VERIFY_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)
# Verify command response packet size with validating MAC
VERIFY_RSP_SIZE_MAC = const(ATCA_RSP_SIZE_32)


""" name Definitions for the Write Command """
# Write command index for zone
WRITE_ZONE_IDX = const(ATCA_PARAM1_IDX)
# Write command index for address
WRITE_ADDR_IDX = const(ATCA_PARAM2_IDX)
# Write command index for data
WRITE_VALUE_IDX = const(ATCA_DATA_IDX)
# Write command index for MAC following short data
WRITE_MAC_VS_IDX = const(9)
# Write command index for MAC following long data
WRITE_MAC_VL_IDX = const(37)
# Write MAC size
WRITE_MAC_SIZE = const(32)
# Write zone bits 2 to 5 are 0.
WRITE_ZONE_MASK = const(0xC3)
# Write zone bit 6: write encrypted with MAC
WRITE_ZONE_WITH_MAC = const(0x40)
# Write zone id OTP
WRITE_ZONE_OTP = const(1)
# Write zone id data
WRITE_ZONE_DATA = const(2)
# Write command response packet size
WRITE_RSP_SIZE = const(ATCA_RSP_SIZE_MIN)


""" Execution times (ms) for ATSHA204A supported commands """
ATSHA204A_EXECUTION_TIME = {
    ATCA_CHECKMAC: 38,
    ATCA_DERIVE_KEY: 62,
    ATCA_GENDIG: 43,
    ATCA_HMAC: 69,
    ATCA_INFO: 2,
    ATCA_LOCK: 24,
    ATCA_MAC: 35,
    ATCA_NONCE: 60,
    ATCA_PAUSE: 2,
    ATCA_RANDOM: 50,
    ATCA_READ: 5,
    ATCA_SHA: 22,
    ATCA_UPDATE_EXTRA: 12,
    ATCA_WRITE: 42
}

""" Execution times (ms) for ATECC108A supported commands """
ATECC108A_EXECUTION_TIME = {
    ATCA_CHECKMAC: 13,
    ATCA_COUNTER: 20,
    ATCA_DERIVE_KEY: 50,
    ATCA_GENDIG: 11,
    ATCA_GENKEY: 115,
    ATCA_HMAC: 23,
    ATCA_INFO: 2,
    ATCA_LOCK: 32,
    ATCA_MAC: 14,
    ATCA_NONCE: 29,
    ATCA_PAUSE: 3,
    ATCA_PRIVWRITE: 48,
    ATCA_RANDOM: 23,
    ATCA_READ: 5,
    ATCA_SHA: 9,
    ATCA_SIGN: 60,
    ATCA_UPDATE_EXTRA: 10,
    ATCA_VERIFY: 72,
    ATCA_WRITE: 26
}

""" Execution times (ms) for ATECC508A supported commands """
ATECC508A_EXECUTION_TIME = {
    ATCA_CHECKMAC: 13,
    ATCA_COUNTER: 20,
    ATCA_DERIVE_KEY: 50,
    ATCA_ECDH: 58,
    ATCA_GENDIG: 11,
    ATCA_GENKEY: 115,
    ATCA_HMAC: 23,
    ATCA_INFO: 2,
    ATCA_LOCK: 32,
    ATCA_MAC: 14,
    ATCA_NONCE: 29,
    ATCA_PAUSE: 3,
    ATCA_PRIVWRITE: 48,
    ATCA_RANDOM: 23,
    ATCA_READ: 5,
    ATCA_SHA: 9,
    ATCA_SIGN: 60,
    ATCA_UPDATE_EXTRA: 10,
    ATCA_VERIFY: 72,
    ATCA_WRITE: 26
}

""" Execution times (ms) for ATECC608A supported commands """
ATECC608A_EXECUTION_TIME = {
    ATCA_AES: 27,
    ATCA_CHECKMAC: 40,
    ATCA_COUNTER: 25,
    ATCA_DERIVE_KEY: 50,
    ATCA_ECDH: 60,
    ATCA_GENDIG: 25,
    ATCA_GENKEY: 115,
    ATCA_INFO: 5,
    ATCA_KDF: 165,
    ATCA_LOCK: 35,
    ATCA_MAC: 55,
    ATCA_NONCE: 20,
    ATCA_PRIVWRITE: 50,
    ATCA_RANDOM: 23,
    ATCA_READ: 5,
    ATCA_SECUREBOOT: 80,
    ATCA_SELFTEST: 250,
    ATCA_SHA: 36,
    ATCA_SIGN: 115,
    ATCA_UPDATE_EXTRA: 10,
    ATCA_VERIFY: 105,
    ATCA_WRITE: 45
}

EXECUTION_TIME = {
    "ATSHA204A": ATSHA204A_EXECUTION_TIME,
    "ATECC108A": ATECC108A_EXECUTION_TIME,
    "ATECC508A": ATECC508A_EXECUTION_TIME,
    "ATECC608A": ATECC608A_EXECUTION_TIME
}
