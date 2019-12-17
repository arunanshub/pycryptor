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
from functools import partial

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(ValueError):
    pass


def _writer(file_path, new_file, method, flag, salt,
            block_size, metadata, nonce_len):
    """Facilitates reading/writing to/from file.
    This function facilitates reading from *file_path* and writing to
    *new_file* with the provided method by looping through each block
    of the file_path of fixed length, specified by *block_size*.

    Note: Since ``cryptography`` module's AESGCM encryption appends a MAC
          after the encrypted part, hence the *nonce* is calculated after
          every block is read for encryption.
          The same is done for decryption, but the appended *nonce* is read
          along with the block data.
          The same *nonce* is never reused.

    :param file_path: File to be written on.
    :param new_file: Name of the encrypted/decrypted file to written upon.
    :param method: The way in which the file must be overwritten.
        	   (encrypt or decrypt).
    :param flag: This is to identify if the method being used is
                 for encryption or decryption.
                 If the flag is *True*, then file is encrypted, and
                 decrypted otherwise.
    :param salt: Salt used for PBKDF2.
    :param block_size: Block-size for reading file.
    :param metadata: Associated data for the file.
    :return: None
    """
    meta_len = len(metadata)

    os.chmod(file_path, stat.S_IRWXU)
    with open(file_path, 'rb') as infile:
        with open(new_file, 'wb+') as outfile:
            outfile_write = outfile.write
            os_urandom_nonce = partial(os.urandom, nonce_len)
            if flag:
                meta_salt = metadata + salt
                outfile_write(meta_salt)

                # create an iterable object for getting blocks.
                # this is a recipe from Python Cookbook.
                blocks = iter(partial(infile.read, block_size), b'')
                for data in blocks:
                    nonce = os_urandom_nonce()
                    outfile_write(nonce + method(nonce=nonce, data=data))
            else:
                infile.seek(meta_len + 32)
                block_size += 12 + 16
                # create an iterable object for getting blocks.
                blocks = iter(partial(infile.read, block_size), b'')
                for data in blocks:
                    nonce, data = data[:12], data[12:]
                    outfile_write(method(nonce=nonce, data=data))


def locker(file_path, password, remove=True, *,
           new_file=None, block_size=64 * 1024, ext='.0DAY',
           iterations=50000, dklen=32,
           metadata=b'Encrypted-with-Pycryptor',
           algo='sha512', method=None, salt_len=32, nonce_len=12):
    """Provides cryptographic file locking/unlocking mechanism.
    This function either encrypts or decrypts the file - *file_path*.
    Encryption or decryption depends upon the file's extension.
    The user's encryption or decryption task is almost automated since
    *encryption* or *decryption* is determined by the file's extension.

    :param file_path: File to be written on.
    :param password: Password to be used for encryption/decryption.
    :param remove: If set to True, the the file that is being
                   encrypted or decrypted will be removed.
                   (Default: True).
    :param block_size = valid block size in int for reading files.
    :param ext = extension to be appended to the files.
    :param iterations = no. of iterations to derive the the key
                        from the password.
    :param algo: The PBKDF2 hashing algorithm to use.
    :param dklen: length of key after PBK derivation.
    :param metadata: associated metadata written to file.
    :param method: set method manually (`encrypt` or `decrypt`)
    :param new_file: set new file path to be written upon.
    :param salt_len: length of the salt for PBKDF2, in bytes.
    :param nonce_len: length of the nonce for cipher.
    :return: None
    """

    # guess the method from the extension,
    # unless the method is explicitly specified
    method = method or ('decrypt' if file_path.endswith(ext) else 'encrypt')

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

    # The file is being decrypted.
    if method == 'decrypt':
        flag = False
        new_file = new_file or os.path.splitext(file_path)[0]

        with open(file_path, 'rb') as file:
            # Check if file can be decrypted.
            check_metadata = file.read(len(metadata))
            if not metadata == check_metadata:
                raise RuntimeError("The file is not supported. "
                                   "The file might be tampered.")

            # Retrieve the *salt*.
            salt = file.read(32)

    # The file is being encrypted
    else:
        flag = True
        new_file = new_file or (file_path + ext)
        salt = os.urandom(salt_len)

    # Create a *password_hash* and *cipher* with
    # required method.
    password_hash = hashlib.pbkdf2_hmac(algo, password,
                                        salt, iterations, dklen)
    cipher_obj = getattr(AESGCM(password_hash), method)
    crp = partial(cipher_obj, associated_data=metadata)

    try:
        _writer(file_path, new_file,
                crp, flag, salt=salt,
                block_size=block_size,
                metadata=metadata,
                nonce_len=nonce_len)
    except InvalidTag:
        os.remove(new_file)
        raise DecryptionError('Invalid Password or tampered data.') from None

    if remove:
        os.remove(file_path)
