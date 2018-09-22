# -*- coding: utf-8 -*-
# pylint: disable=E0401
import pyb
import machine
import ubinascii
import uctypes
import ustruct
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
            bus=machine.I2C(
                1,
                # scl=machine.Pin.board.X9,
                # sda=machine.Pin.board.X10,
                freq=BAUDRATE
            ),
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
        # Generate Wake Token
        machine.Pin.board.X10.value(0)
        utime.sleep_us(80)
        machine.Pin.board.X10.value(1)

        # Wait tWHI + tWLO
        utime.sleep_us(WAKE_DELAY)

    def idle(self):
        self._bus.writeto(self._address, b'\x02')

    def sleep(self):
        self._bus.writeto(self._address, b'\x01')

    def execute(self, packet):
        self.wake()

        header = ustruct.pack('<B', 0x03)
        length = ustruct.pack('<B', 7 + packet.request_length)
        params = length + packet.to_buffer()
        params += self.at_crc(params)

        self._bus.writeto(self._address, header + params)

        utime.sleep_ms(packet.delay)

        self._bus.readfrom_into(
            self._address,
            packet.response_data_mv[:1]
        )
        self._bus.readfrom_into(
            self._address,
            packet.response_data_mv[1:packet.response_data_mv[0]]
        )

        packet.response_data = packet.response_data[:packet.response_data_mv[0]]

        err, msg = self.is_error(packet.response_data)
        if err != ATCA_STATUS.ATCA_SUCCESS:
            raise ValueError(
                "execute: 0x{:02x} ({:s}) - {:s}".format(
                    err, msg, ubinascii.hexlify(packet.response_data),
                )
            )
