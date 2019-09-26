#!/usr/bin/python
# -*- coding: utf-8 -*-
# Locker v4.3 (follows new protocol)
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
from functools import partial
from struct import pack, unpack

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(ValueError):
    pass


class Locker:
    """Cryptographic file Locker written as class :)

    Uses cryptography as backend for it's working.
    The class is made in a way where user can directly change the attribute's
    value to fit his needs.

    As an example, we will use a file : 'file.txt'

    locker's signature:
    Locker(file_path, method='auto')

    >>> with open('file.txt', 'wb') as file:
            file.write(b'hello crypto world')

    >>> lck = Locker('file.txt')

    >>> lck.method
    'encrypt'
    If nothing is provided in method, it would be inferred from
    the file extension.

    >>> lck.ext
    '.0DAY'
    The default extension for Locker, change the method if you want different
    extension.

    >>> lck.locker(new_file='file2.txt')
    ValueError: Cannot encrypt file without password.
    Calling locker without setting password results in error.

    >>> lck.password = b'hello crypto world'
    Set the password like by changing password attribute
    Please not that once the password is set, no method can be changed except
    `password` itself.
    Password is not a readable attribute and using `password`, the
    `password_hash` and `salt` is calculated.

    Likewise, all the attributes can be changed to suite your purpose.
    """

    ext = '.0DAY'
    block_size = 64 * 1024
    iterations = 50000
    dklen = 32
    metadata = b'Encrypted-using-Pycryptor'
    algo = 'sha512'

    def __init__(self, file_path, method='auto'):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file '{file_path}' was not found.")
        self.file_path = file_path

        if method == 'auto':
            self.method = 'decrypt' if file_path.endswith(self.ext) \
                               else 'encrypt'
        else:
            self.method = method

        self.password_hash = None

    def _check_method(self, method_name):
        """
        Checks for method name's validity.
        """

        if method_name not in ['encrypt', 'decrypt', 'auto']:
            raise ValueError(
                      f"Invalid method: '{method_name}'. "
                      "Method can be 'encrypt', 'decrypt' or 'auto' only.")

    def __setattr__(self, name, value):
        """
        Set the attributes of class while checking for any potential errors.
        """

        # Ckeck if password is set.
        if self.__dict__.get('password_hash'):

            # Let the user change the password
            if name == 'password':
                del self.password_hash
                object.__setattr__(self, name, value)

            # Cannot change any method's value
            else:
                raise AttributeError(f"Cannot change '{name}' when password"
                                      "is set.")

        # Let the user change the methods when password is unset.
        else:
            # Check the method name's validity.
            if name == 'method':
                self._check_method(value)
            object.__setattr__(self, name, value)

    @property
    def password(self):
        raise AttributeError("password attribute is not readable.")

    @password.setter
    def password(self, pwd):

        if self.method == 'encrypt':
            self.salt = os.urandom(32)
            self.flag = True

        else:
            self.flag = False
            with open(self.file_path, 'rb') as file:
                # Check if file can be decrypted.
                check_metadata = file.read(len(self.metadata))
                if not self.metadata == check_metadata:
                    raise RuntimeError("The file is not supported. "
                                       "The file might be tampered.")

                # Retrieve the *salt*.
                self.salt = file.read(32)

        self.password_hash = hashlib.pbkdf2_hmac(self.algo, pwd,
                                                 self.salt,
                                                 self.iterations, self.dklen)

    @staticmethod
    def _writer(file_path, new_file, method, flag, **kwargs):
        """Facilitates reading/writing to/from file.
        This function facilitates reading from *file_path* and writing to
        *new_file* with the provided method by looping through each line
        of the file_path of fixed length, specified by *block_size*.

        Note: Since ``cryptography`` module's AESGCM encryption appends a MAC
              after the encrypted part, hence the *nonce* is calculated after
              every block is read for encryption.
              The same is done for decryption, but the appended *nonce* is read
              along with the block data.
              The same *nonce* is never reused.

        :param file_path: File to be written on.
        :param new_file: Name of the encrypted/decrypted file to written upon.
        :param method: The way in which the file must be written.
                       (encrypt or decrypt).
        :param flag: This is to identify if the method being used is
                     for encryption or decryption.
                     If the flag is *True*, then file is encrypted, and
                     decrypted otherwise.
        :param kwargs: salt, block_size, metadata
        :return: None
        """

        salt = kwargs['salt']
        block_size = kwargs['block_size']
        metadata = kwargs['write_metadata']

        meta_len = len(metadata)

        os.chmod(file_path, stat.S_IRWXU)
        with open(file_path, 'rb') as infile:
            with open(new_file, 'wb+') as outfile:

                if flag:
                    meta_salt = pack(f'{meta_len}s32s', metadata, salt)
                    outfile.write(meta_salt)
                    while True:
                        data = infile.read(block_size)
                        if not data:
                            break
                        nonce = os.urandom(12)
                        outfile.write(nonce + method(nonce=nonce, data=data))

                else:
                    infile.seek(meta_len + 32)
                    block_size += 12 + 16
                    while True:
                        data = infile.read(block_size)
                        if not data:
                            break
                        nonce, data = data[:12], data[12:]
                        outfile.write(method(nonce=nonce, data=data))

    def locker(self, new_file=None, remove=True):
        """Provides file locking/unlocking mechanism
        This function either encrypts or decrypts the file - *file_path*.
        Encryption or decryption depends upon the file's extension.
        The user's encryption or decryption task is almost automated since
        *encryption* or *decryption* is determined by the file's extension.
        
        :param new_file: Set new file path to be written upon.
        :param remove: If set to True, the the file that is being
                       encrypted or decrypted will be removed.
                       (Default: True).
        :return: None
        """

        if not self.password_hash:
            raise ValueError(f"Cannot {self.method} file without password.")

        if new_file is None:
            new_file = self.file_path + self.ext
        else:
            if os.path.exists(new_file):
                if os.path.samefile(file_path, new_file):
                    raise ValueError(f'Cannot process with the same file.')
                os.remove(new_file)

        # Create a *password_hash* and *cipher* with
        # required method.
        cipher_obj = getattr(AESGCM(self.password_hash), self.method)
        crp = partial(cipher_obj, associated_data=self.metadata)

        try:
            self._writer(self.file_path, new_file,
                         crp, self.flag, salt=self.salt,
                         block_size=self.block_size,
                         write_metadata=self.metadata)
        except InvalidTag:
            os.remove(new_file)
            raise DecryptionError('Invalid Password or tampered data.') \
                from None

        if remove:
            os.remove(self.file_path)
