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
BAUDRATE = micropython.const(1000000)
WAKE_DELAY = micropython.const(150)
RX_RETRIES = micropython.const(20)
SUPPORTED_DEVICES = {0x50: "ATECC508A", 0x60: "ATECC608A"}


class ATECCX08A(ATECCBasic):
    """ ATECCX08A over I2C """

    def __init__(
            self,
            bus=machine.I2C(1, freq=133000),
            address=I2C_ADDRESS, retries=RX_RETRIES):

        if address not in bus.scan():
            raise ATCA_EXECUTIONS.NoDevicesFoundError()

        self._bus = bus
        self._address = address
        self._retries = retries
        try:
            self._device = SUPPORTED_DEVICES[self.atcab_info()[1+2]]
        except KeyError:
            raise ATCA_EXECUTIONS.UnsupportedDeviceError()

    def __str__(self):
        return "<{:s} address=0x{:02x} retries={:d}>".format(
            self._device or self.__class__.__name__,
            self._address,
            self._retries
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
                if isinstance(self._device, str):
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
                    packet._response_data = response[:response[0]]
                    return
                elif err == ATCA_STATUS.ATCA_WAKE_SUCCESS:
                    return
                elif err == ATCA_STATUS.ATCA_WATCHDOG_ABOUT_TO_EXPIRE:
                    self.sleep()
                else:
                    if exc is not None:
                        raise exc(ubinascii.hexlify(response[:response[0]]))
            except OSError:
                retries -= 1
        else:
            raise ATCA_EXECUTIONS.GenericError("max retry")
