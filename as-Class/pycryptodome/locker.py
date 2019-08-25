#!/usr/bin/python
# -*- coding: utf-8 -*-
# Locker v4.0 (follows new protocol)
# Implemented as class
#
# =============================================================================
# MIT License

# Copyright (c) 2019 Arunanshu Biswas

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =============================================================================

import hashlib
import os
import stat
from struct import pack, unpack

from Cryptodome.Cipher import AES


class DecryptionError(ValueError):
    pass


class Locker:
    ext = '.0DAY'
    block_size = 64 * 1024
    nonce_len = 12
    mac_len = 16
    salt_len = 32
    iterations = 50000
    dklen = 32
    _metadata = b'Encrypted-using-Pycryptor'

    def __init__(self, file_path):
        if os.path.exists(file_path):
            self.file_path = file_path
        else:
            raise FileNotFoundError(f"No such file '{file_path}' found.")

        self._salt = None
        self.password_hash = None
        self._flag = None
        self._mac = None
        self._nonce = None
        self._valid = None

    def __setattr__(self, name, value):

        # Prevent changing any attribute after the password
        # attribute is set.
        if name not in ['password']:
            if not self.__dict__.get('password_hash'):
                object.__setattr__(self, name, value)
            else:
                raise AttributeError(f"Cannot change '{name}' once password "
                                     f"is set.")

        # If user is changing password, let them do it.
        else:
            if self.__dict__.get('password_hash'):
                del self.password_hash
            object.__setattr__(self, name, value)

    @property
    def password(self):
        # password set here would be converted to *password_hash*.
        raise AttributeError('password Attribute is not readable.')

    @password.setter
    def password(self, password):
        if not self.file_path.endswith(self.ext):
            self._salt = os.urandom(32)
            self._nonce = os.urandom(12)
            self._mac = None
            self._flag = True
            self._valid = True

        else:
            self._flag = False
            with open(self.file_path, 'rb') as file:
                metadata = file.read(len(self._metadata))
                if not metadata == self._metadata:
                    self._valid = False
                self._valid = True

                self._mac, self._nonce, self._salt = unpack('16s12s32s',
                                                            file.read(16 +
                                                                      12 + 32))

        self.password_hash = hashlib.pbkdf2_hmac('sha512', password,
                                                 self._salt,
                                                 self.iterations,
                                                 self.dklen)

    @classmethod
    def _writer(cls, file_path, new_file, method, flag, **kwargs):
        """Facilitates reading/writing to/from file.
    This function facilitates reading from *file_path* and writing to
    *new_file* with the provided method by looping through each line
    of the file_path of fixed length, specified by *block_size*.

    :param file_path: File to be written on.
    :param new_file: Name of the encrypted/decrypted file to written upon.
    :param method: The way in which the file must be overwritten.
                   (encrypt or decrypt).
    :param flag: This is to identify if the method being used is
                 for encryption or decryption.
                 If the *flag* is *True* then the *nonce* value
                 is written to the end of the *new_file*.
                 If the *flag* is *False*, then the *nonce* is written to
                 *file_path*.
    :param kwargs: slat, nonce, mac_func, block_size, metadata
    :return: None
    """

        salt = kwargs['salt']
        nonce = kwargs['nonce']
        mac_func = kwargs['mac_func']
        metadata = kwargs['write_metadata']

        meta_len = len(metadata)

        os.chmod(file_path, stat.S_IRWXU)
        with open(file_path, 'rb') as infile:
            with open(new_file, 'wb+') as outfile:
                if flag:

                    # Create a placeholder for writing the *mac*.
                    # and append *nonce* and *salt* before encryption.
                    # Add a metadata to the file for identity.
                    plh_nonce_salt = pack(f'{meta_len}s16s12s32s',
                                          metadata,
                                          b'0' * 16, nonce, salt)
                    outfile.write(plh_nonce_salt)

                else:
                    # Moving ahead towards the encrypted data.
                    infile.seek(meta_len + cls.mac_len +
                                cls.nonce_len + cls.salt_len)

                # Loop through the *infile*, generate encrypted data
                # and write it to *outfile*.
                while True:
                    part = infile.read(cls.block_size)
                    if not part:
                        break
                    outfile.write(method(part))

                if flag:
                    outfile.seek(meta_len)
                    outfile.write(mac_func())

    def locker(self, remove=True):
        """Provides file locking/unlocking mechanism
    This function either encrypts or decrypts the file - *file_path*.
    Encryption or decryption depends upon the file's extension.
    The user's encryption or decryption task is almost automated since
    *encryption* or *decryption* is determined by the file's extension.

    :param remove: If set to True, the the file that is being
                   encrypted or decrypted will be removed.
                   (Default: True).
    :return: None
    """

        if not self.password_hash:
            raise ValueError("Cannot process file without a valid password.")

        if not self._valid:
            raise RuntimeError("The file is not supported. "
                               "The file might be tampered.")

        # The file is being encrypted.
        if self._flag:
            method = 'encrypt'
            new_file = self.file_path + self.ext

        # The file is being decrypted.
        else:
            method = 'decrypt'
            new_file = os.path.splitext(self.file_path)[0]

        # Create a *cipher* with required method.
        cipher_obj = AES.new(self.password_hash, AES.MODE_GCM,
                             nonce=self._nonce)
        crp = getattr(cipher_obj.update(self._metadata), method)

        self._writer(self.file_path, new_file,
                     crp, self._flag,
                     nonce=self._nonce,
                     mac_func=cipher_obj.digest,
                     mac_val=self._mac,
                     salt=self._salt,
                     write_metadata=self._metadata, )

        if not self._flag:
            try:
                cipher_obj.verify(self._mac)
            except ValueError:
                os.remove(new_file)
                raise DecryptionError('Invalid Password or tampered data.')

        if remove:
            os.remove(self.file_path)
