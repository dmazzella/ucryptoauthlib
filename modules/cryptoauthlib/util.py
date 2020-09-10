# -*- coding: utf-8 -*-
# pylint: disable=E0401
import sys
import uctypes
from ubinascii import hexlify

"""
SlotConfig (Bytes 20 to 51)

             15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
            -------------------------------------------------
            |           |           |  |  |  |  |           |
            -------------------------------------------------
             |           |           |  |  |  |  |           
 WriteConfig -           |           |  |  |  |  |           
                WriteKey -           |  |  |  |  |           
                            IsSecret -  |  |  |  |           
                            EncryptRead -  |  |  |           
                                LimitedUse -  |  |           
                                        NoMac -  |           
                                         ReadKey -           


ReadKey : 4 = 3-0
NoMac : 1 = 4;
LimitedUse : 1 = 5
EncryptRead : 1 = 6
IsSecret : 1 = 7
WriteKey : 4 = 11-8
WriteConfig : 4 = 15-12
"""

SLOT_CONFIG_STRUCT = {
    "ReadKey": uctypes.BFUINT32 | 0 | 0 << uctypes.BF_POS | 4 << uctypes.BF_LEN,
    "NoMac": uctypes.BFUINT32 | 0 | 4 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "LimitedUse": uctypes.BFUINT32 | 0 | 5 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "EncryptRead": uctypes.BFUINT32 | 0 | 6 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "IsSecret": uctypes.BFUINT32 | 0 | 7 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "WriteKey": uctypes.BFUINT32 | 0 | 8 << uctypes.BF_POS | 4 << uctypes.BF_LEN,
    "WriteConfig": uctypes.BFUINT32 | 0 | 12 << uctypes.BF_POS | 4 << uctypes.BF_LEN
}


def dump_slot(slot, index=None, stream=None):
    slot_stuct = uctypes.struct(
        uctypes.addressof(slot),
        SLOT_CONFIG_STRUCT,
        uctypes.LITTLE_ENDIAN
    )

    if not stream:
        stream = sys.stderr

    index_s = "[{:d}]".format(index) if isinstance(index, int) else ""

    stream.write("Slot{:s}({:s}):".format(index_s, hexlify(slot)))
    stream.write("ReadKey({:04b})".format(slot_stuct.ReadKey))
    stream.write("NoMac({:d})".format(slot_stuct.NoMac))
    stream.write("LimitedUse({:d})".format(slot_stuct.LimitedUse))
    stream.write("EncryptRead({:d})".format(slot_stuct.EncryptRead))
    stream.write("IsSecret({:d})".format(slot_stuct.IsSecret))
    stream.write("WriteKey({:04b})".format(slot_stuct.WriteKey))
    stream.write("WriteConfig({:04b})\n".format(slot_stuct.WriteConfig))
    return stream if stream not in (sys.stderr, sys.stdout) else None


"""
KeyConfig (Bytes 96 through 127)

             15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
            -------------------------------------------------
            |     |  |  |           |  |  |  |  |        |  |
            -------------------------------------------------
             |     |  |  |           |  |  |  |  |        |  
      X509id -     |  |  |           |  |  |  |  |        |  
               RFU -  |  |           |  |  |  |  |        |  
     IntrusionDisable -  |           |  |  |  |  |        |  
                 AuthKey -           |  |  |  |  |        |  
                             ReqAuth -  |  |  |  |        |  
                              ReqRandom -  |  |  |        |  
                                  Lockable -  |  |        |  
                                      KeyType -  |        |  
                                        PubInfo  -        |  
                                                  Private -  

Private : 1 = 0
PubInfo : 1 = 1
KeyType : 3 = 4-2
Lockable : 1 = 5
ReqRandom : 1 = 6
ReqAuth : 1 = 7
AuthKey : 4 = 11-8
IntrusionDisable : 1 = 12
RFU : 1 = 13
X509id : 2 = 15-14
"""

KEY_CONFIG_STRUCT = {
    "Private": uctypes.BFUINT32 | 0 | 0 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "PubInfo": uctypes.BFUINT32 | 0 | 1 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "KeyType": uctypes.BFUINT32 | 0 | 2 << uctypes.BF_POS | 3 << uctypes.BF_LEN,
    "Lockable": uctypes.BFUINT32 | 0 | 5 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "ReqRandom": uctypes.BFUINT32 | 0 | 6 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "ReqAuth": uctypes.BFUINT32 | 0 | 7 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "AuthKey": uctypes.BFUINT32 | 0 | 8 << uctypes.BF_POS | 4 << uctypes.BF_LEN,
    "IntrusionDisable": uctypes.BFUINT32 | 0 | 12 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "RFU": uctypes.BFUINT32 | 0 | 13 << uctypes.BF_POS | 1 << uctypes.BF_LEN,
    "X509id": uctypes.BFUINT32 | 0 | 14 << uctypes.BF_POS | 2 << uctypes.BF_LEN
}


def dump_key(key, index=None, stream=None):
    key_stuct = uctypes.struct(
        uctypes.addressof(key),
        KEY_CONFIG_STRUCT,
        uctypes.LITTLE_ENDIAN
    )

    if not stream:
        stream = sys.stderr

    index_k = "[{:d}]".format(index) if isinstance(index, int) else ""

    stream.write("Key{:s}({:s}):".format(index_k, hexlify(key)))
    stream.write("Private({:d})".format(key_stuct.Private))
    stream.write("PubInfo({:d})".format(key_stuct.PubInfo))
    stream.write("KeyType({:03b})".format(key_stuct.KeyType))
    stream.write("Lockable({:d})".format(key_stuct.Lockable))
    stream.write("ReqRandom({:d})".format(key_stuct.ReqRandom))
    stream.write("ReqAuth({:d})".format(key_stuct.ReqAuth))
    stream.write("AuthKey({:04b})".format(key_stuct.AuthKey))
    stream.write("IntrusionDisable({:d})" .format(key_stuct.IntrusionDisable))
    stream.write("RFU({:d})".format(key_stuct.RFU))
    stream.write("X509id({:02b})\n".format(key_stuct.X509id))
    return stream if stream not in (sys.stderr, sys.stdout) else None


def dump_configuration(configuration, stream=None):
    if not isinstance(configuration, (bytes, bytearray, memoryview)):
        raise TypeError()

    if len(configuration) != 128:
        raise ValueError("expected: 128 got: {:d}".format(len(configuration)))

    if not stream:
        stream = sys.stderr

    c = memoryview(configuration)

    stream.write("SN<0:3>({:s})\n".format(hexlify(c[0:4])))
    stream.write("RevNum({:s})\n".format(hexlify(c[4:8])))
    stream.write("SN<4:8>({:s})\n".format(hexlify(c[8:13])))
    stream.write("AES_Enable({:08b})\n".format(c[13]))
    stream.write("I2C_Enable({:08b})\n".format(c[14]))
    stream.write("Reserved({:08b})\n".format(c[15]))
    stream.write("I2C_Address({:08b})\n".format(c[16]))
    stream.write("Reserved({:08b})\n".format(c[17]))
    stream.write("CountMatch({:08b})\n".format(c[18]))
    stream.write("ChipMode({:08b})\n".format(c[19]))
    SlotConfig = c[20:52]
    stream.write("SlotConfig:\n")
    for idx, slot_buf in enumerate(range(0, 32, 2)):
        dump_slot(SlotConfig[slot_buf:slot_buf+2], index=idx, stream=stream)
    stream.write("Counter[0]({:s})\n".format(hexlify(c[52:60])))
    stream.write("Counter[1]({:s})\n".format(hexlify(c[60:68])))
    stream.write("UserLock({:08b})\n".format(c[68]))
    stream.write("VolatileKeyPermission({:08b})\n".format(c[69]))
    stream.write("SecureBoot({:s})\n".format(hexlify(c[70:72])))
    stream.write("KdflvLoc({:08b})\n".format(c[72]))
    stream.write("KdflvStr({:s})\n".format(hexlify(c[73:75])))
    stream.write("Reserved({:s})\n".format(hexlify(c[75:84])))
    stream.write("UserExtra({:08b})\n".format(c[84]))
    stream.write("UserExtraAdd({:08b})\n".format(c[85]))
    stream.write("LockValue({:08b})\n".format(c[86]))
    stream.write("LockConfig({:08b})\n".format(c[87]))
    stream.write("SlotLocked({:s})\n".format(hexlify(c[88:90])))
    stream.write("ChipOptions({:s})\n".format(hexlify(c[90:92])))
    stream.write("X509format({:s})\n".format(hexlify(c[92:96])))
    KeyConfig = c[96:128]
    stream.write("KeyConfig:\n")
    for idx, key_buf in enumerate(range(0, 32, 2)):
        dump_key(KeyConfig[key_buf:key_buf+2], index=idx, stream=stream)
    return stream if stream not in (sys.stderr, sys.stdout) else None
