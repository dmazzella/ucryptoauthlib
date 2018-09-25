# -*- coding: utf-8 -*-
import logging
from cryptoauthlib.device import ATECC508A

from atecc508a import tests_info
from atecc508a import tests_sha

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("atecc508a")

atecc508a = ATECC508A()
log.debug("%s", atecc508a)

tests_info.run(atecc508a=atecc508a)
tests_sha.run(atecc508a=atecc508a)

# import atecc508a
