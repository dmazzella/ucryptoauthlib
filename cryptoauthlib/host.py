# -*- coding: utf-8 -*-
# pylint: disable=import-error
import uhashlib

###########################################################################
#            CryptoAuthLib Host API methods for SHA command               #
###########################################################################


def atcah_sha256(message):
    return uhashlib.sha256(message).digest()
