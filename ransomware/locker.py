#!/usr/bin/python
# -*- coding: utf-8 -*-
# Locker v4.0 (follows new protocol)
# Implemented as function
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


def _writer(file_path, new_file, method, flag, **kwargs):
    """Facilitates reading/writing to file.
    This function facilitates reading from *file_path* and writing to
    *new_file* with the provided method by looping through each line
    of the file_path of fixed length, specified by *block_size*.
      Usage
     -------
    file_path = File to be written on.
     new_file = Name of the encrypted/decrypted file to written upon.
       method = The way in which the file must be overwritten.
                (encrypt or decrypt).
         flag = This is to identify if the method being used is
                for encryption or decryption.
                If the *flag* is *True* then the *nonce* value
                is written to the end of the *new_file*.
                If the *flag* is *False*, then the *nonce* is written to
                *file_path*.
    """

    salt = kwargs['salt']
    nonce = kwargs['nonce']
    mac_func = kwargs['mac_func']
    block_size = kwargs['block_size']

    os.chmod(file_path, stat.S_IRWXU)
    with open(file_path, 'rb') as infile:
        with open(new_file, 'wb+') as outfile:
            if flag:

                # Create a placeholder for writing the *mac*.
                # and append *nonce* and *salt* before encryption.
                # Also, add a 3 Byte metadata indicating encrypted file.
                plh_nonce_salt = pack('3s16s12s32s', b'enc',
                                      b'0' * 16, nonce, salt)
                outfile.write(plh_nonce_salt)

            else:

                # Moving ahead towards the encrypted data.
                infile.seek(3 + 16 + 12 + 32)

            # Loop through the *infile*, generate encrypted data
            # and write it to *outfile*.
            while True:
                part = infile.read(block_size)
                if not part:
                    break
                outfile.write(method(part))

            if flag:
                outfile.seek(3)
                outfile.write(mac_func())


def locker(file_path, password, remove=True, **kwargs):
    """Provides file locking/unlocking mechanism
    This function either encrypts or decrypts the file - *file_path*.
    Encryption or decryption depends upon the file's extension.
    The user's encryption or decryption task is almost automated since
    *encryption* or *decryption* is determined by the file's extension.
      Usage
     -------
     file_path = File to be written on.
     password = Password to be used for encryption/decryption.
       remove = If set to True, the the file that is being
                encrypted or decrypted will be removed.
                (Default: True).
    """

    if kwargs:
        block_size = kwargs.get('block_size', 64 * 1024)
        ext = kwargs.get('ext', '.0DAY')
        iterations = kwargs.get('iterations', 50000)
        dklen = kwargs.get('dklen', 32)
    else:
        block_size = 64 * 1024
        ext = '.0DAY'
        iterations = 50000
        dklen = 32

    # The file is being decrypted.
    if file_path.endswith(ext):
        method = 'decrypt'
        flag = False
        new_file = os.path.splitext(file_path)[0]

        # Retrieve the *nonce* and *salt*.
        with open(file_path, 'rb') as file:
            metadata = file.read(3)
            if not metadata == b'enc':
                raise RuntimeError("The file is not supported. "
                                   "The file might be tampered.")
            mac, nonce, salt = unpack('16s12s32s',
                                      file.read(16 + 12 + 32))

    # The file is being encrypted.
    else:
        method = 'encrypt'
        flag = True
        new_file = file_path + ext
        nonce = os.urandom(12)
        salt = os.urandom(32)
        mac = None

    # Create a *password_hash* and *cipher* with
    # required method.
    password_hash = hashlib.pbkdf2_hmac('sha512', password,
                                        salt, iterations, dklen)
    cipher_obj = AES.new(password_hash, AES.MODE_GCM,
                         nonce=nonce)
    crp = getattr(cipher_obj, method)

    _writer(file_path, new_file,
            crp, flag,
            nonce=nonce,
            mac_func=cipher_obj.digest,
            mac_val=mac,
            salt=salt, block_size=block_size, )

    if not flag:
        try:
            cipher_obj.verify(mac)
        except ValueError:
            os.remove(new_file)
            raise DecryptionError('Invalid Password or tampered data.') from None

    if remove:
        os.remove(file_path)
