#!/usr/bin/python
# -*- coding: utf-8 -*-
# locker v3.1
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

from struct import pack, unpack, calcsize
from Cryptodome.Cipher import AES

NONCE_SIZE = 12
MAC_LEN = 16
BLOCK_SIZE = 64 * 1024
EXT = '.0DAY'


class DecryptionError(ValueError):
    pass


def _writer(file_path, new_file, method, flag, **kwargs):
    """Facilitates file writing
    This function takes care of reading from the file - *file_path*
    and writing to the new file - *new_file* with the provided method by
    looping through each line of the file_path of fixed length, specified by
    BLOCK_SIZE in global namespace.
  
        Usage
       -------
    file_path = File to be written on.

     new_file = Name of the encrypted/decrypted file to written upon.

       method = The way in which the file must be overwritten.
                (encrypt or decrypt)

         flag = This is to identify if the method being used is
                for encryption or decryption.

                 If the *flag* is *True* then the *nonce* value
                 and a *mac* tag function are accepted.
                 If the *flag* is *False*, *nonce* value and a
                 previously read *mac* value are accepted.
    """

    if kwargs:
        nonce = kwargs['nonce']
        mac_func = kwargs['mac_function']
        mac_val = kwargs['mac_value']

    os.chmod(file_path, stat.S_IRWXU)
    with open(file_path, 'rb+') as infile:
        with open(new_file, 'wb+') as outfile:    
            while True:
                part = infile.read(BLOCK_SIZE)
                if not part:
                    break
                new = method(part)
                outfile.write(new)

            # If the file is being encrypted, generate and
            # write the *mac* tag and *nonce* value to the *new_file*.

            if flag:
                # Generating the *mac* tag after encryption.
                derived_mac_val = mac_func()

                nonce_mac = pack('<{}s{}s'.format(NONCE_SIZE, MAC_LEN),
                                 nonce, derived_mac_val)
                outfile.write(nonce_mac)

            # If the file is being decrypted, put the *nonce*
            # and received *mac* value back into the file to
            # restore the previous condition of the encrypted file.

            if not flag:
                infile.seek(0, 2)
                infile.write(pack('<{}s{}s'.format(NONCE_SIZE, MAC_LEN),
                                  nonce, mac_val))


def locker(file_path, password, remove=True):
    """Provides file locking/unlocking mechanism
    This function either encrypts or decrypts the file - *file_path*.
    Encryption or decryption depends upon the file's extension.
    The user's encryption or decryption task is almost automated since
    *encryption* or *decryption* is determined by the file's extension.
  
    Added:
        After the *file_path* decryption, decrypted file's verification
        is done. If it fails, either the Password is incorrect or the
        encrypted data was supposedly tampered with.

    Usage
   -------
   file_path = File to be written on.

   password = Key to be used for encryption/decryption.
              - Raises DataDecryptionError if *Password* is incorrect
                or Encrypted data has been tampered with.

     remove = If set to True, the the file that is being
              encrypted or decrypted will be removed.
              (Default: True).
  """

    try:

        # The file is being decrypted

        if file_path.endswith(EXT):
            method = 'decrypt'
            flag = False

            # Read the *nonce* and *mac* values.
            # Please note that we are receiving the *nonce*
            # and *mac* values.

            with open(file_path, 'rb+') as f:
                f.seek(-(NONCE_SIZE + MAC_LEN), 2)
                (nonce, mac) = unpack('<{}s{}s'.format(NONCE_SIZE, MAC_LEN),
                                      f.read())

            # Remove the *mac* and *nonce* from the encrypted file.
            # If not removed, Incorrect decryption will occur.

            orig_file_size = os.path.getsize(file_path) - (NONCE_SIZE + MAC_LEN)
            os.truncate(file_path, orig_file_size)
            new_file = os.path.splitext(file_path)[0]

        else:

            # The file is being encrypted.

            method = 'encrypt'
            flag = True
            new_file = file_path + EXT

            # Generate a *nonce* and set the mac to None,
            # As the *mac* ***will not be received*** this time
            # but it will be generated after encryption.
            #
            # Generation will take place in _writer(...)
            nonce = os.urandom(12)
            mac = None

        key = hashlib.sha3_256(password).digest()

        # ############# CIPHER GENERATION PORTION #############
        # A cipher object will take care of the all
        # the required mac_tag and verification.
        # AES-GCM-256 chosen for security and authentication

        cipher_obj = AES.new(key, AES.MODE_GCM, nonce)
        crp = getattr(cipher_obj, method)
        mac_func = getattr(cipher_obj, 'digest')
        verifier = getattr(cipher_obj, 'verify')

        # ############# FILE WRITING PORTION ###################
        # Read from the *file_path* and,
        # write to the *new_file* using _writer defined above.

        _writer(file_path,
                new_file,
                crp,
                flag,
                nonce=nonce,
                mac_function=mac_func,
                mac_value=mac, )

        # ################ VERIFICATION PORTION ##################
        # Verify the file for integrity if the
        # current file is being decrypted.

        if not flag:
            try:
                verifier(mac)

            except ValueError:

                # Remove the incorrectly decrypted file
                # and raise DataDecryptionError.

                os.remove(new_file)
                
                raise DecryptionError("Either Password is incorrect or "
                                      "Encrypted Data has been tampered.")

        #########################################################

        # If remove set to True, delete the file
        # that is being worked upon.

        if remove:
            os.remove(file_path)

    except Exception as err:
        raise err
