#!/usr/bin/python3
# Locker v0.4.5 (follows new protocol)
# Implemented as function
#
# =============================================================================
# MIT License

# Copyright (c) 2020 Arunanshu Biswas

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
from struct import unpack
from functools import partial

from importlib.util import find_spec

# Compatibility with Crypto (pycryptodome)
if find_spec('Crypto') and int(__import__('Crypto').__version__[0]) >= 3:
    from Crypto.Cipher import AES
else:
    from Cryptodome.Cipher import AES


class DecryptionError(ValueError):
    pass


def locker(file_path,
           password,
           remove=True,
           *,
           method=None,
           new_file=None,
           blocksize=16 * 1024,
           ext='.0DAY',
           iterations=50000,
           dklen=32,
           metadata=b'Encrypted-with-Pycryptor',
           algo='sha256',
           salt_len=32,
           nonce_len=12):
    """Provides file locking/unlocking mechanism
    This function either encrypts or decrypts the file - *file_path*.
    Encryption or decryption depends upon the file's extension.
    The user's encryption or decryption task is almost automated since
    *encryption* or *decryption* is determined by the file's extension.

    :param file_path: File to be written on.
    :param password: Password to be used for encryption/decryption.
    :param remove: If set to True, the the file that is being
                   encrypted or decrypted will be removed.
                   (Default: True).
    :param algo: The PBKDF2 hashing algorithm to use.
    :param metadata: associated metadata written to file.
    :param dklen: length of key after key derivation.
    :param iterations: no. of iterations for key derivation.
    :param ext: extension to be used for the new file.
    :param blocksize: valid block size in int for reading files.
    :param new_file: set new file path to be written upon.
    :param method: set method manually (`encrypt` or `decrypt`)
    :param nonce_len: Length of nonce to use, in bytes.
    :param salt_len: Length of salt used in PBKDF2, in bytes.
    :return: None
    """
    # check for the validity of the given filepaths, exts and methods.
    method = _prepare(file_path, new_file, ext, method)

    # The file is being decrypted.
    if method == 'decrypt':
        flag = False
        new_file = new_file or os.path.splitext(file_path)[0]

        # Retrieve the *nonce* and *salt*.
        with open(file_path, 'rb') as file:
            if not file.read(len(metadata)) == metadata:
                raise RuntimeError("The file is not supported. "
                                   "The file might be tampered.")

            tag, nonce, salt = unpack(f'16s{nonce_len}s{salt_len}s',
                                      file.read(16 + nonce_len + salt_len))

    # The file is being encrypted.
    else:
        flag = True
        new_file = new_file or (file_path + ext)
        nonce = os.urandom(nonce_len)
        salt = os.urandom(salt_len)
        tag = None

    # Create a *password_hash* and *cipher* with required method.
    password_hash = hashlib.pbkdf2_hmac(algo, password, salt, iterations,
                                        dklen)
    cipher_obj = AES.new(
        password_hash,
        AES.MODE_GCM,
        nonce=nonce,
    ).update(metadata)

    try:
        with open(file_path, 'rb') as infile, \
            open(new_file, 'wb') as outfile:
            _writer(infile,
                    outfile,
                    cipher=cipher_obj,
                    flag=flag,
                    tag=tag,
                    nonce=nonce,
                    salt=salt,
                    blocksize=blocksize,
                    metadata=metadata)
    except ValueError:
        os.remove(new_file)
        raise DecryptionError('Invalid Password or tampered data.') from None

    if remove:
        os.remove(file_path)


def _writer(infile, outfile, cipher, flag, tag, salt, nonce, blocksize,
            metadata):
    write = outfile.write

    if flag:
        write(metadata + bytes(16) + nonce + salt)
        crpup = cipher.encrypt
    else:
        infile.seek(len(metadata) + 16 + len(nonce + salt))
        crpup = cipher.decrypt

    buf = memoryview(bytearray(blocksize))
    blocks = iter(partial(infile.readinto, buf), 0)

    for i in blocks:
        if i < blocksize:
            buf = buf[:i]
        crpup(buf, buf)
        write(buf)

    if flag:
        outfile.seek(len(metadata))
        outfile.write(cipher.digest())
    else:
        cipher.verify(tag)


def _prepare(file1, file2, ext, method):
    """
    Preparation done before proceeding further for
    encryption or decryption.
    """
    _check_same_file(file1, file2)
    return _check_method(file1, ext, method)


def _check_same_file(file1, file2=None):
    """Checks if two files given are same."""
    if file2 is not None:
        if os.path.exists(file2):
            if os.path.samefile(file1, file2):
                raise ValueError(f'Cannot process with the same file.')


def _check_method(file, ext, method):
    """
    Checks the validity of method given.
    If not given, it is guessed from the file's extension.
    """
    if method is None:
        return ('decrypt' if os.path.splitext(file)[1] == ext else 'encrypt')
    else:
        if method not in ['encrypt', 'decrypt']:
            raise ValueError(f"Invalid method: '{method}'. Method can be "
                             f"'encrypt' or 'decrypt' only.")
        else:
            return method
