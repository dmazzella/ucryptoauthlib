# ucryptoauthlib

Lightweight driver for Microchip Crypto Authentication secure elements written in pure python for micropython.

WARNING: this project is in beta stage and is subject to changes of the
code-base, including project-wide name changes and API changes.

Features
---------------------

- Allows PyBoard to control Microchip Crypto Authentication secure elements

Usage
---------------------

- PyBoard basic connection:

</br>
<img src="https://raw.githubusercontent.com/dmazzella/ucryptoauthlib/master/docs/PYBOARD_ATECCX08A_bb.png" width="80%" height="80%" alt="PYBOARD plus ATECCX08A"/>
</br>


- BASIC

```python
MicroPython v1.9.4-754-g5146e7949-dirty on 2018-12-13; PYBv1.1 with STM32F405RG
Type "help()" for more information.
>>> from cryptoauthlib.device import ATECCX08A
>>> device = ATECCX08A()
>>> print(device)
<ATECC608A address=0x60 retries=20>
>>>
```

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
INFO:ateccX08a SIGN SUCCEDED
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

1. Copy 'cryptoauthlib' into PyBoard's filesystem
2. Freeze package using FROZEN_MPY_DIR

Software
---------------------

Currently supported commands are:

* INFO
* LOCK
* NONCE
* RANDOM
* READ (1)
* SHA (1)
* WRITE (1)
* VERIFY (1)
* GENKEY
* SIGN

  (1) Not all features are implemented, see follow list for details

Currently implemented methods are:

- [x] atcab_version(self)
- [x] atcab_get_addr(self, zone, slot=0, block=0, offset=0)
- [x] atcab_get_zone_size(self, zone, slot=0)
- [ ] atcab_checkmac(self, mode, key_id, challenge, response,  other_data)
- [ ] atcab_counter(self, mode, counter_id)
- [ ] atcab_counter_increment(self, counter_id)
- [ ] atcab_counter_read(self, counter_id)
- [ ] atcab_derivekey(self, mode, key_id, mac)
- [ ] atcab_ecdh_base(self, mode, key_id, public_key)
- [ ] atcab_ecdh(self, key_id, public_key)
- [ ] atcab_ecdh_enc(self, key_id, public_key, read_key, read_key_id)
- [ ] atcab_ecdh_ioenc(self, key_id, public_key, io_key)
- [ ] atcab_ecdh_tempkey(self, public_key)
- [ ] atcab_ecdh_tempkey_ioenc(self, public_key, io_key)
- [ ] atcab_gendig(self, zone, key_id, other_data)
- [x] atcab_genkey_base(self, mode, key_id, other_data=None)
- [x] atcab_genkey(self, key_id)
- [x] atcab_get_pubkey(self, key_id)
- [ ] atcab_hmac(self, mode, key_id)
- [x] atcab_info_base(self, mode=0)
- [x] atcab_info(self)
- [ ] atcab_kdf(self, mode, key_id, details, message)
- [x] atcab_lock(self, mode, crc=0)
- [x] atcab_lock_config_zone(self)
- [x] atcab_lock_config_zone_crc(self, crc)
- [x] atcab_lock_data_zone(self)
- [x] atcab_lock_data_zone_crc(self, crc)
- [x] atcab_lock_data_slot(self, slot)
- [ ] atcab_mac(self, mode, key_id, challenge)
- [x] atcab_nonce_base(self, mode, zero=0, numbers=None)
- [x] atcab_nonce(self, numbers=None)
- [x] atcab_nonce_load(self, target, numbers=None)
- [x] atcab_nonce_rand(self, numbers=None)
- [x] atcab_challenge(self, numbers=None)
- [x] atcab_challenge_seed_update(self, numbers=None)
- [ ] atcab_priv_write(self, key_id, priv_key, write_key_id, write_key)
- [x] atcab_random(self)
- [x] atcab_read_zone(self, zone, slot=0, block=0, offset=0, length=0)
- [x] atcab_read_serial_number(self)
- [x] atcab_read_bytes_zone(self, zone, slot=0, block=0, offset=0, length=0)
- [x] atcab_is_slot_locked(self, slot)
- [x] atcab_is_locked(self, zone)
- [x] atcab_read_config_zone(self)
- [ ] atcab_read_enc(self, key_id, block, data, enc_key, enc_key_id)
- [ ] atcab_cmp_config_zone(self, config_data)
- [ ] atcab_read_sig(self, slot)
- [x] atcab_read_pubkey(self, slot)
- [ ] atcab_secureboot(self, mode, param2, digest, signature)
- [ ] atcab_secureboot_mac(self, mode, digest, signature, num_in, io_key)
- [ ] atcab_selftest(self, mode, param2)
- [x] atcab_sha_base(self, mode=0, data=b'', key_slot=None)
- [x] atcab_sha(self, data)
- [ ] atcab_sha_hmac(self, data, key_slot, target)
- [x] atcab_sign_base(self, mode, key_id)
- [x] atcab_sign(self, key_id, message)
- [x] atcab_sign_internal(self, key_id, is_invalidate=False, is_full_sn=False)
- [x] atcab_updateextra(self, mode, value)
- [x] atcab_verify(self, mode, key_id, signature, public_key=None, other_data=None, mac=None)
- [x] atcab_verify_extern(self, message, signature, public_key)
- [ ] atcab_verify_extern_mac(self, message, signature, public_key, num_in, io_key, is_verified)
- [x] atcab_verify_stored(self, message, signature, key_id)
- [ ] atcab_verify_stored_mac(self, message, signature, key_id, num_in, io_key, is_verified)
- [ ] atcab_verify_validate(self,  key_id, signature, other_data, is_verified)
- [ ] atcab_verify_invalidate(self,  key_id, signature, other_data, is_verified)
- [x] atcab_write(self, zone, address, value=None, mac=None)
- [x] atcab_write_zone(self, zone, slot=0, block=0, offset=0, data=None)
- [x] atcab_write_bytes_zone(self, zone, slot=0, offset=0, data=None)
- [x] atcab_write_pubkey(self, slot, public_key)
- [x] atcab_write_config_zone(self, config_data)
- [ ] atcab_write_enc(self, key_id, block, data, enc_key, enc_key_id)
- [ ] atcab_write_config_counter(self, counter_id, counter_value)

Hardware
---------------------

Currently supported devices are:

- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)
