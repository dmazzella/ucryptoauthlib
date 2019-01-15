# -*- coding: utf-8 -*-
# pylint: disable=E0401
import machine
import ubinascii
import utime
import micropython

import cryptoauthlib.constant as ATCA_CONSTANTS
import cryptoauthlib.exceptions as ATCA_EXECUTIONS
import cryptoauthlib.status as ATCA_STATUS
from cryptoauthlib.basic import ATECCBasic


I2C_ADDRESS = micropython.const(0xC0 >> 1)
BAUDRATE = micropython.const(160000)
WAKE_DELAY = micropython.const(150)
RX_RETRIES = micropython.const(20)
SUPPORTED_DEVICES = ("ATECC508A", "ATECC608A")

class ATECCX08A(ATECCBasic):
    """ ATECCX08A over I2C """

    def __init__(
            self,
            bus=machine.I2C(1, freq=BAUDRATE),
            address=I2C_ADDRESS, retries=RX_RETRIES,
            device="ATECC508A"):

        if address not in bus.scan():
            raise ATCA_EXECUTIONS.NoDevicesFoundError()

        if device not in SUPPORTED_DEVICES:
            raise ATCA_EXECUTIONS.UnsupportedDeviceError(
                "ATECCX08A expected: {!s} got: {:s}".format(
                    SUPPORTED_DEVICES,
                    device
                )
            )

        self._bus = bus
        self._address = address
        self._retries = retries
        self._device = device

    def __str__(self):
        return "<{:s} address=0x{:02x} retries={:d} device={:s}>".format(
            self.__class__.__name__,
            self._address,
            self._retries,
            self._device
        )

    @property
    def device(self):
        return self._device

    def wake(self):
        self._bus.writeto(self._address, b'\x00\x00')

    def idle(self):
        self._bus.writeto(self._address, b'\x02')

    def sleep(self):
        self._bus.writeto(self._address, b'\x01')

    def execute(self, packet):

        retries = self._retries
        while retries:
            try:
                self.wake()
                # Wait tWHI + tWLO
                utime.sleep_us(WAKE_DELAY)

                # Set device name
                packet.device = self._device

                # Send the command
                self._bus.writeto(self._address, b'\x03' + packet.to_buffer())

                # Delay for execution time
                utime.sleep_ms(packet.delay)

                response = packet.response_data_mv

                # Receive the response
                self._bus.readfrom_into(self._address, response[0:1])
                self._bus.readfrom_into(self._address, response[1:response[0]])

                # Check response
                err, exc = self.is_error(response)
                if err == ATCA_STATUS.ATCA_SUCCESS:
                    packet.response_data = response[:response[0]]
                    return
                elif err == ATCA_STATUS.ATCA_WAKE_SUCCESS:
                    return
                elif err == ATCA_STATUS.ATCA_WATCHDOG_ABOUT_TO_EXPIRE:
                    self.sleep()
                else:
                    if exc is not None:
                        raise exc(ubinascii.hexlify(response))
            except OSError:
                retries -= 1
        else:
            raise ATCA_EXECUTIONS.GenericError("max retry")
