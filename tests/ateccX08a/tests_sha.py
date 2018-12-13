# -*- coding: utf-8 -*-
import logging
from binascii import hexlify

from cryptoauthlib.constant import (
    SHA_MODE_SHA256_START,
    SHA_MODE_SHA256_UPDATE,
    SHA_MODE_SHA256_END,
    ATCA_SHA256_BLOCK_SIZE
)

log = logging.getLogger("ateccX08a.tests_sha")


def run(device=None):
    if not device:
        raise ValueError("device")

    expected = b"\x1a:\xa5E\x04\x94S\xaf\xdf\x17\xe9\x89\xa4\x1f\xa0\x97\x94\xa5\x1b\xd5\xdb\x9167gU\x0c\x0f\n\xf3'\xd4"
    message = b'\xBC' * ATCA_SHA256_BLOCK_SIZE
    packet = device.atcab_sha(message)
    assert expected in bytes(packet.response_data), bytes(packet.response_data)
    log.debug("atcab_sha: %s", hexlify(packet.response_data))

    expected = b'p~\x97\xe6\xf8d]\xf5\xd8\x068.g\x01\xc8\xe2\xe2\x16`\x17\xf6\nV\xe6\xaa\xc0\xc2\xd2\xdb\xbb"\x81'
    message = b'\x5A' * ATCA_SHA256_BLOCK_SIZE
    packet = device.atcab_sha_base(SHA_MODE_SHA256_START)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_UPDATE, message)
    packet = device.atcab_sha_base(SHA_MODE_SHA256_END)
    assert expected in bytes(packet.response_data), bytes(packet.response_data)
    log.debug("atcab_sha_base: %s", hexlify(packet.response_data))

    # test HW SHA with a long message > SHA block size and not an exact SHA block-size increment
    expected = b'\xa9"\x18VCp\xa0W\'?\xf4\x85\xa8\x07?2\xfc\x1f\x14\x12\xec\xa2\xe3\x0b\x81\xa8\x87v\x0ba1r'
    message = b'\xBC' * (ATCA_SHA256_BLOCK_SIZE + 63)
    packet = device.atcab_sha(message)
    assert expected in bytes(packet.response_data), bytes(packet.response_data)
    log.debug("atcab_sha %d: %s", len(message), hexlify(packet.response_data))

    # test HW SHA with a short message < SHA block size and not an exact SHA block-size increment
    expected = b'0?\xf8\xba@\xa2\x06\xe7\xa9P\x02\x1e\xf5\x10f\xd4\xa0\x01Tu2>\xe9\xf2J\xc8\xc9c)\x8f4\xce'
    message = b'\xBC' * 10
    packet = device.atcab_sha(message)
    assert expected in bytes(packet.response_data), bytes(packet.response_data)
    log.debug("atcab_sha %d: %s", len(message), hexlify(packet.response_data))

    # test NIST HW SHA
    expected = b'\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae"#\xb0\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad'
    message = "abc"
    packet = device.atcab_sha(message)
    assert expected in bytes(packet.response_data), bytes(packet.response_data)
    log.debug("atcab_sha nist 1: %s", hexlify(packet.response_data))

    expected = b'$\x8dja\xd2\x068\xb8\xe5\xc0&\x93\x0c>`9\xa3<\xe4Yd\xff!g\xf6\xec\xed\xd4\x19\xdb\x06\xc1'
    message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    packet = device.atcab_sha(message)
    assert expected in bytes(packet.response_data), bytes(packet.response_data)
    log.debug("atcab_sha nist 2: %s", hexlify(packet.response_data))
