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
MicroPython v1.9.4-754-g5146e7949-dirty on 2018-12-13; PYBv1.1 with STM32F405RG
Type "help()" for more information.
>>> import ateccX08a; ateccX08a.test()
INFO:ateccX08a <ATECC608A address=0x60 retries=20>
INFO:ateccX08a INFO SUCCEDED
INFO:ateccX08a SHA SUCCEDED
INFO:ateccX08a RANDOM SUCCEDED
INFO:ateccX08a NONCE SUCCEDED
INFO:ateccX08a READ SUCCEDED
INFO:ateccX08a WRITE SUCCEDED
INFO:ateccX08a LOCK SKIPPED
INFO:ateccX08a VERIFY SUCCEDED
>>> 
```

Enable DEBUG:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
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
- LOCK
- NONCE
- RANDOM
- READ (1)
- SHA (1)
- WRITE (1)
- VERIFY (1)

  (1) Not all features are implemented

Hardware
---------------------

Currently supported devices are:

- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)
