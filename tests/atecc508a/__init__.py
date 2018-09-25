# -*- coding: utf-8 -*-
import logging
from cryptoauthlib.device import ATECC508A

from atecc508a import tests_info
from atecc508a import tests_sha

log = logging.getLogger("atecc508a")

atecc508a = ATECC508A()
log.info("%s", atecc508a)

tests_info.run(atecc508a=atecc508a)
log.info("INFO SUCCEDED")
tests_sha.run(atecc508a=atecc508a)
log.info("SHA SUCCEDED")

# import logging
# logging.basicConfig(level=logging.DEBUG)
# import atecc508a
