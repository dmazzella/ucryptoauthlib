# ucryptoauthlib

Lightweight driver for Microchip Crypto Authentication secure elements written in pure python for micropython.

WARNING: this project is in beta stage and is subject to changes of the
code-base, including project-wide name changes and API changes.

Features
---------------------

- Allows PyBoard to control Microchip Crypto Authentication secure elements

Usage
---------------------

- TESTS:

```python
MicroPython v1.9.4-575-g6ea6c7cc9-dirty on 2018-09-25; PYBv1.1 with STM32F405RG
Type "help()" for more information.
>>> import atecc508a
INFO:atecc508a <ATECC508A address=0x60 retries=20>
INFO:atecc508a INFO SUCCEDED
INFO:atecc508a SHA SUCCEDED
>>>
```

Enable DEBUG:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
import atecc508a
```

External dependencies
---------------------

Only for tests:
'logging' already available into folder 'micropython-lib' of this repository

Install 'cryptoauthlib' into the PyBoard
---------------------

- Copy 'cryptoauthlib' into PyBoard's filesystem

Hardware
---------------------

Currently supported devices are:

- [ATECC508A](http://www.microchip.com/ATECC508A)
