#!/usr/bin/python3
# Locker v0.4.2 (follows new protocol)
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
from struct import unpack
from functools import partial

from pkgutil import find_loader

# Compatibility with Crypto (pycryptodome)
if find_loader('Crypto') and int(__import__('Crypto').__version__[0]) >= 3:
    from Crypto.Cipher import AES
else:
    from Cryptodome.Cipher import AES


class DecryptionError(ValueError):
    pass


def _writer(file_path, new_file, method, flag, salt,
            nonce, mac_func, block_size, metadata):
    """Facilitates reading/writing to/from file.
    This function facilitates reading from *file_path* and writing to
    *new_file* with the provided method by looping through each block
    of the file_path of fixed length, specified by *block_size*.

    :param file_path: File to be written on.
    :param new_file: Name of the encrypted/decrypted file to written upon.
    :param method: The way in which the file must be overwritten.
                   (encrypt or decrypt).
    :param flag: This is to identify if the method being used is for
                 encryption or decryption.
                 If the flag is *True*, then file is encrypted, and
                 decrypted otherwise.
    :param salt: Salt from the PBKDF2
    :param metadata: Associated data to be written to the file
    :param block_size: Reading block size, in bytes.
    :param mac_func: bound method of AES object for calculating MAC-tag.
    :param nonce: nonce used with the key.
    :return: None
    """

    meta_len = len(metadata)

    os.chmod(file_path, stat.S_IRWXU)
    with open(file_path, 'rb') as infile:
        with open(new_file, 'wb+') as outfile:
            outfile_write = outfile.write
            if flag:
                # Create a placeholder for writing the *mac*.
                # and append *nonce* and *salt* before encryption.
                # Also, add a metadata indicating encrypted file.
                plh_nonce_salt = metadata + (b'\x00' * 16) + nonce + salt
                outfile_write(plh_nonce_salt)

            else:
                # Moving ahead towards the encrypted data.
                infile.seek(meta_len + 16 + 12 + 32)

            # create an iterable object for getting blocks.
            # this is a recipe from Python Cookbook.
            blocks = iter(partial(infile.read, block_size), b'')
            for data in blocks:
                outfile_write(method(data))

            # write mac-tag to the file.
            if flag:
                outfile.seek(meta_len)
                outfile.write(mac_func())


def locker(file_path, password, remove=True, method=None, new_file=None,
           block_size=64 * 1024, ext='.0DAY', iterations=50000, dklen=32,
           metadata=b'Encrypted-with-Pycryptor', algo='sha512', salt_len=32,
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
    :param dklen: length of key after PBK derivation.
    :param iterations: no. of iterations to derive the the key from
                       the password.
    :param ext: extension to be appended to the files.
    :param block_size: valid block size in int for reading files.
    :param new_file: set new file path to be written upon.
    :param method: set method manually (`encrypt` or `decrypt`)
    :param nonce_len: Length of nonce to use, in bytes.
    :param salt_len: Length of salt used in PBKDF2, in bytes.
    :return: None
    """

    # check for new-file's existence
    if new_file is not None:
        if os.path.exists(new_file):
            if os.path.samefile(file_path, new_file):
                raise ValueError(f'Cannot process with the same file.')
            os.remove(new_file)

    # check for method validity
    if method is not None:
        if method not in ['encrypt', 'decrypt']:
            raise ValueError(f'Invalid method: `{method}`. '
                             'Method can be "encrypt" or "decrypt" only.')

    # guess the method from the extension,
    # unless the method is explicitly specified
    method = method or ('decrypt' if file_path.endswith(ext) else 'encrypt')

    # The file is being decrypted.
    if method == 'decrypt':
        flag = False
        new_file = new_file or os.path.splitext(file_path)[0]

        # Retrieve the *nonce* and *salt*.
        with open(file_path, 'rb') as file:
            check_metadata = file.read(len(metadata))
            if not check_metadata == metadata:
                raise RuntimeError("The file is not supported. "
                                   "The file might be tampered.")

            mac, nonce, salt = unpack('16s12s32s',
                                      file.read(16 + nonce_len + salt_len))

    # The file is being encrypted.
    else:
        flag = True
        new_file = new_file or (file_path + ext)
        nonce = os.urandom(nonce_len)
        salt = os.urandom(salt_len)
        mac = None

    # Create a *password_hash* and *cipher* with required method.
    password_hash = hashlib.pbkdf2_hmac(algo, password,
                                        salt, iterations, dklen)
    cipher_obj = AES.new(password_hash, AES.MODE_GCM, nonce=nonce)
    crp = getattr(cipher_obj.update(metadata), method)

    _writer(file_path, new_file,
            crp, flag,
            nonce=nonce,
            mac_func=cipher_obj.digest,
            salt=salt, block_size=block_size,
            metadata=metadata)

    if not flag:
        try:
            cipher_obj.verify(mac)
        except ValueError:
            os.remove(new_file)
            raise DecryptionError('Invalid Password or tampered data.') from None

    if remove:
        os.remove(file_path)
