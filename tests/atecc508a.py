# -*- coding: utf-8 -*-
# pylint: disable=E0401
import logging

from cryptoauthlib.device import ATECC508A

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("atecc508a")


def main():
    atecc508a = ATECC508A()
    log.debug("%s", atecc508a)
    log.debug("atcab_info: %s", atecc508a.atcab_info())

# from atecc508a import main; main()
