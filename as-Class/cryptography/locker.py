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
from functools import partial

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(ValueError):
    pass


class Locker:

    ext = '.0DAY'
    block_size = 64 * 1024
    nonce_len = 12
    salt_len = 32
    iterations = 50000
    dklen = 32

    def __init__(self, file_path):
        if os.path.exists(file_path):
            self.file_path = file_path
        else:
            raise FileNotFoundError(f"No such file '{file_path}' found.")

        self._salt = None
        self.password_hash = None
        self._flag = None
        self._nonce = None

    def __setattr__(self, name, value):
        # Prevent changing any attribute after the password
        # arrtibute is set.
        if name != 'password':
            if not self.__dict__.get('password_hash'):
                object.__setattr__(self, name, value)
            else:
                raise AttributeError(f"Cannot change '{name}' once password "
                                     f"is set.")

        # If user is changing password, let them do it.
        else:
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
            self._flag = True

        else:
            self._flag = False
            with open(self.file_path, 'rb') as file:
                self._nonce, self._salt = unpack('12s32s',
                                                 file.read(12 + 32))

        self.password_hash = hashlib.pbkdf2_hmac('sha512', password,
                                                 self._salt,
                                                 self.iterations,
                                                 self.dklen)

    @classmethod
    def _writer(cls, file_path, new_file, method, flag, **kwargs):
        """Facilitates reading/writing to file.
        This function facilitates reading from *file_path* and writing to
        *new_file* with the provided method by looping through each line
        of the file_path of fixed length, specified by *block_size*.

          Usage
         -------

        file_path = File to be written on.

         new_file = Name of the encrypted/decrypted file to written upon.

           method = The way in which the file must be overwritten.
                    (encrypt or decrypt)

             flag = This is to identify if the method being used is
                    for encryption or decryption.
                    If the *flag* is *True* then the *nonce* value
                    is written to the end of the *new_file*.
                    If the *flag* is *False*, then the *nonce* is written to
                    *file_path*.
        """

        salt = kwargs['salt']
        nonce = kwargs['nonce']

        os.chmod(file_path, stat.S_IRWXU)
        with open(file_path, 'rb') as fin:
            with open(new_file, 'wb+') as fout:
                if flag:
                    # Append *nonce* and *salt* before encryption.
                    nonce_salt = pack('12s32s', nonce, salt)
                    fout.write(nonce_salt)
                    block_size = cls.block_size

                else:
                    # Moving ahead towards the encrypted data.
                    # Setting new block_size for reading encrypted data
                    fin.seek(cls.nonce_len + cls.salt_len)
                    block_size = cls.block_size + 16

                # Loop through the *fin*, generate encrypted data
                # and write it to *fout*.
                while True:
                    part = fin.read(block_size)
                    if not part:
                        break
                    fout.write(method(data=part))

    def locker(self, remove=True):
        """Provides file locking/unlocking mechanism
        This function either encrypts or decrypts the file - *file_path*.
        Encryption or decryption depends upon the file's extension.
        The user's encryption or decryption task is almost automated since
        *encryption* or *decryption* is determined by the file's extension.

          Usage
         -------

          remove = If set to True, the the file that is being
                   encrypted or decrypted will be removed.
                   (Default: True).
        """

        # The file is being encrypted.
        if self._flag:
            method = 'encrypt'
            new_file = self.file_path + self.ext

        # The file is being encrypted.
        else:
            method = 'decrypt'
            new_file = os.path.splitext(self.file_path)[0]

        # Create a *cipher* with required method.
        cipher_obj = getattr(AESGCM(self.password_hash), method)
        crp = partial(cipher_obj, nonce=self._nonce, associated_data=None)

        try:
            self._writer(self.file_path, new_file,
                         crp, self._flag,
                         nonce=self._nonce,
                         salt=self._salt, )
        except InvalidTag:
            os.remove(new_file)
            raise DecryptionError('Invalid Password or tampered data.')

        if remove:
            os.remove(self.file_path)
