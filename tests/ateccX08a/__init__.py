# -*- coding: utf-8 -*-
import logging
from cryptoauthlib.device import ATECCX08A

from ateccX08a import tests_info
from ateccX08a import tests_sha
from ateccX08a import tests_random

log = logging.getLogger("ateccX08a")


def test(name="ATECC608A"):
    device = ATECCX08A(device=name)
    log.info("%s", device)

    tests_info.run(device)
    log.info("INFO SUCCEDED")

    tests_sha.run(device)
    log.info("SHA SUCCEDED")

    tests_random.run(device)
    log.info("RANDOM SUCCEDED")

# import logging
# logging.basicConfig(level=logging.DEBUG)

# import ateccX08a; ateccX08a.test("ATECC508A")
# import ateccX08a; ateccX08a.test("ATECC608A")
