# -*- coding: utf-8 -*-
# pylint: disable=E0401
import machine
import ubinascii
import utime
import micropython

import cryptoauthlib.constant as ATCA_CONSTANTS
import cryptoauthlib.status as ATCA_STATUS
from cryptoauthlib.basic import ATECCBasic


I2C_ADDRESS = micropython.const(0xC0 >> 1)
BAUDRATE = micropython.const(160000)
WAKE_DELAY = micropython.const(150)
RX_RETRIES = micropython.const(20)


class ATECC508A(ATECCBasic):
    """ ATECC508A over I2C """

    def __init__(
            self,
            bus=machine.I2C(1, freq=BAUDRATE),
            address=I2C_ADDRESS, retries=RX_RETRIES):
        self._bus = bus
        if address not in self._bus.scan():
            raise ValueError("ATECC508A not ready.")

        self._address = address
        self._retries = retries

    def __str__(self):
        return "<{:s} address=0x{:02x} retries={:d}>".format(
            self.__class__.__name__,
            self._address,
            self._retries
        )

    def wake(self):
        self._bus.writeto(self._address, b'\x00\x00')

    def idle(self):
        self._bus.writeto(self._address, b'\x02')

    def sleep(self):
        self._bus.writeto(self._address, b'\x01')

    def execute(self, packet):
        self.wake()
        # Wait tWHI + tWLO
        utime.sleep_us(WAKE_DELAY)

        # Send the command
        self._bus.writeto(self._address, b'\x03' + packet.to_buffer())

        # Delay for execution time
        utime.sleep_ms(packet.delay)

        response = packet.response_data_mv

        # Receive the response
        self._bus.readfrom_into(self._address, response[0:1])
        self._bus.readfrom_into(self._address, response[1:response[0]])
        
        # Check response
        err, msg = self.is_error(response)
        if err != ATCA_STATUS.ATCA_SUCCESS:
            raise ValueError(
                "execute: 0x{:02x} ({:s}) - {:s}".format(
                    err, msg, ubinascii.hexlify(response),
                )
            )

        packet.response_data = response[:response[0]]
