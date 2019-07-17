#!/usr/bin/python
# -*- coding: utf-8 -*-
# Same Locker, but uses cryptography module instead...
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
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
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
from functools import partial
from struct import pack, unpack

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Locker:
    NONCE_SIZE = 12
    SALT_LEN = 32
    BLOCK_SIZE = 64 * 1024
    EXT = '.0DAY'

    # todo: improve documentation

    def __init__(self, file_path, **kwargs):
        self._salt = None
        self.password_hash = None
        self._flag = None

        if os.path.exists(file_path):
            self.file_path = file_path
            self._flag = False if file_path.endswith(self.EXT) else True
        else:
            raise FileNotFoundError('No such file {} found.'.format(file_path))

        if kwargs:
            self.password = kwargs['password']

    @property
    def password(self):
        raise AttributeError('password Attribute is not readable.')

    @password.setter
    def password(self, password):
        if self._flag:
            self._salt = os.urandom(32)

        else:
            with open(self.file_path, 'rb') as f:
                f.seek(-self.SALT_LEN, 2)
                self._salt = f.read()

        self.password_hash = hashlib.pbkdf2_hmac('sha512',
                                                 password,
                                                 self._salt,
                                                 50000,
                                                 32)

    @classmethod
    def _writer(cls, file_path, new_file, method, flag, **kwargs):
        """Facilitates reading/writing to file.
        This function facilitates reading from *file_path* and writing to
        *new_file* with the provided method by looping through each line
        of the file_path of fixed length, specified by BLOCK_SIZE in global
        namespace.

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

        if kwargs:
            nonce = kwargs['nonce']
            salt = kwargs['salt']

        if not flag:
            # Setting new BLOCK_SIZE for reading encrypted data
            cls.BLOCK_SIZE += 16

        os.chmod(file_path, stat.S_IRWXU)
        with open(file_path, 'rb+') as infile:
            with open(new_file, 'wb+') as outfile:
                # Loop through the *infile*, generate encrypted data
                # and write it to *outfile*.
                try:
                    while True:
                        part = infile.read(cls.BLOCK_SIZE)
                        if not part:
                            break
                        new_data = method(data=part)
                        outfile.write(new_data)

                except InvalidTag as err:
                    infile.seek(0, 2)
                    infile.write(pack('<{}s{}s'.format(cls.NONCE_SIZE,
                                                       cls.SALT_LEN),
                                      nonce, salt))

                    # Reset the BLOCK_SIZE to original value
                    raise err

                # Write the nonce into the *new_file* for future use.

                if flag:
                    outfile.write(pack('<{}s{}s'.format(cls.NONCE_SIZE,
                                                        cls.SALT_LEN),
                                       nonce, salt))

                # Write the nonce to the *file_path* to restore the
                # original file condition

                else:
                    infile.seek(0, 2)
                    infile.write(pack('<{}s{}s'.format(cls.NONCE_SIZE,
                                                       cls.SALT_LEN),
                                      nonce, salt))

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

        # The file is being decrypted
        try:
            if not self._flag:
                method = 'decrypt'
                new_file = os.path.splitext(self.file_path)[0]

                # Retrieve the nonce and remove it from the
                # encrypted file

                with open(self.file_path, 'rb+') as f:
                    f.seek(-(self.NONCE_SIZE + self.SALT_LEN), 2)
                    nonce, _ = unpack('<{}s{}s'.format(self.NONCE_SIZE,
                                                       self.SALT_LEN),
                                      f.read())

                orig_size = os.path.getsize(self.file_path) - (self.NONCE_SIZE +
                                                               self.SALT_LEN)
                os.truncate(self.file_path, orig_size)

            # The file is being encrypted
            else:
                method = 'encrypt'
                new_file = self.file_path + self.EXT

                nonce = os.urandom(self.NONCE_SIZE)

            # Create a cipher with the required method

            key = self.password_hash
            cipher = getattr(AESGCM(key), method)

            # Create a partial function with default values.

            crp = partial(cipher, nonce=nonce, associated_data=None)

            # Read from *file_path* and write to the *new_file*
            try:
                Locker._writer(self.file_path,
                               new_file,
                               crp,
                               self._flag,
                               nonce=nonce,
                               salt=self._salt, )
            except InvalidTag:
                os.remove(new_file)
                raise InvalidTag('Invalid Password or tampered data.')

            if remove:
                os.remove(self.file_path)
        
            return self
        except Exception as err:
            raise err

    def __repr__(self):
        password_check = True if self.password_hash is not None else False
        method_check = 'encrypt' if self._flag else 'decrypt'

        return '<Locker: method=`{method}`, password={pwd}>'.format(
            method=method_check,
            pwd=password_check, )
