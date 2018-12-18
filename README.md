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
MicroPython v1.9.4-679-ge328a5d46-dirty on 2018-10-29; PYBv1.1 with STM32F405RG
Type "help()" for more information.
>>> import ateccX08a; ateccX08a.test("ATECC608A")
INFO:ateccX08a <ATECCX08A address=0x60 retries=20 device=ATECC608A>
INFO:ateccX08a INFO SUCCEDED
INFO:ateccX08a SHA SUCCEDED
INFO:ateccX08a RANDOM SUCCEDED
INFO:ateccX08a NONCE SUCCEDED
INFO:ateccX08a READ SUCCEDED
>>> 
```

Enable DEBUG:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
import ateccX08a
```

External dependencies
---------------------

Only for tests:
'logging' already available into folder 'micropython-lib' of this repository

Install 'cryptoauthlib' into the PyBoard
---------------------

- Copy 'cryptoauthlib' into PyBoard's filesystem

Software
---------------------

Currently supported commands are:

- INFO
- SHA
- RANDOM
- NONCE
- READ (1)

  (1) Not all features are implemented

Hardware
---------------------

Currently supported devices are:

- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)
