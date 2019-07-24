#!/usr/bin/python
# -*- coding: utf-8 -*-
# locker v3.3
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
from struct import pack, unpack

from Cryptodome.Cipher import AES


class DecryptionError(ValueError):
    pass


class Locker:
    NONCE_SIZE = 12
    SALT_LEN = 32
    MAC_LEN = 16
    BLOCK_SIZE = 64 * 1024
    EXT = '.0DAY'

    # todo: improve documentation

    def __init__(self, file_path):
        if os.path.exists(file_path):
            self.file_path = file_path
        else:
            raise FileNotFoundError('No such file {} found.'.format(file_path))

        self._salt = None
        self.password_hash = None
        self._flag = None
            
    def __setattr__(self, name, value):
        if name != 'password':
            if self.__dict__.get('password_hash'):
                raise AttributeError('Attribute cannot be set when password is present.')
            else:
                object.__setattr__(self, name, value)
        else:
            # to prevent AttributeError caused while
            # changing password.
            if self.__dict__.get('password_hash'):
                del self.password_hash
            object.__setattr__(self, name, value)
    
    @property
    def password(self):
        raise AttributeError('password Attribute is not readable.')

    @password.setter
    def password(self, password):
        
        if len(password) < 8:
            raise ValueError(f'password must be longer than 8 bytes.')
        
        if not self.file_path.endswith(self.EXT):
            self._salt = os.urandom(32)
            self._flag = True
        
        else:
            with open(self.file_path, 'rb') as f:
                f.seek(-self.SALT_LEN, 2)
                self._salt = f.read()
                self._flag = False
        self.password_hash = hashlib.pbkdf2_hmac('sha512',
                                                 password,
                                                 self._salt,
                                                 50000,
                                                 32)
        

    @classmethod
    def _writer(cls, file_path, new_file, method, flag, **kwargs):
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
            salt = kwargs['salt']

        os.chmod(file_path, stat.S_IRWXU)
        with open(file_path, 'rb+') as infile:
            with open(new_file, 'wb+') as outfile:
                while True:
                    part = infile.read(cls.BLOCK_SIZE)
                    if not part:
                        break
                    new = method(part)
                    outfile.write(new)

                # If the file is being encrypted, generate and
                # write the *mac* tag and *nonce* value to the *new_file*.

                if flag:
                    # Generating the *mac* tag after encryption.
                    derived_mac_val = mac_func()

                    nonce_mac = pack('<{}s{}s{}s'.format(cls.NONCE_SIZE,
                                                         cls.MAC_LEN,
                                                         cls.SALT_LEN),
                                     nonce, derived_mac_val, salt)
                    outfile.write(nonce_mac)

                # If the file is being decrypted, put the *nonce*
                # and received *mac* value back into the file to
                # restore the previous condition of the encrypted file.

                else:
                    infile.seek(0, 2)
                    infile.write(pack('<{}s{}s{}s'.format(cls.NONCE_SIZE,
                                                          cls.MAC_LEN,
                                                          cls.SALT_LEN),
                                      nonce, mac_val, salt))

    def locker(self, remove=True):
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
        
        remove = If set to True, the the file that is being
                  encrypted or decrypted will be removed.
                  (Default: True).
      """

        try:

            # The file is being decrypted

            if not self._flag:
                method = 'decrypt'
                flag = False

                # Read the *nonce* and *mac* values.
                # Please note that we are receiving the *nonce*
                # and *mac* values.

                with open(self.file_path, 'rb+') as f:
                    f.seek(-(self.NONCE_SIZE + self.MAC_LEN + self.SALT_LEN), 2)
                    (nonce, mac, _) = unpack('<{}s{}s{}s'.format(self.NONCE_SIZE,
                                                                 self.MAC_LEN,
                                                                 self.SALT_LEN),
                                             f.read())

                # Remove the *mac* and *nonce* from the encrypted file.
                # If not removed, Incorrect decryption will occur.

                orig_file_size = os.path.getsize(self.file_path) - \
                                                        (self.NONCE_SIZE + 
                                                        self.MAC_LEN + 
                                                        self.SALT_LEN)
                
                os.truncate(self.file_path, orig_file_size)
                new_file = os.path.splitext(self.file_path)[0]

            else:

                # The file is being encrypted.

                method = 'encrypt'
                flag = True
                new_file = self.file_path + self.EXT

                # Generate a *nonce* and set the mac to None,
                # As the *mac* ***will not be received*** this time
                # but it will be generated after encryption.
                #
                # Generation will take place in _writer(...)
                nonce = os.urandom(self.NONCE_SIZE)
                mac = None

            # ================= CIPHER GENERATION PORTION ============
            # A cipher object will take care of the all
            # the required mac_tag and verification.
            # AES-GCM-256 chosen for security and authentication

            cipher_obj = AES.new(self.password_hash, AES.MODE_GCM, nonce)
            crp = getattr(cipher_obj, method)
            mac_func = getattr(cipher_obj, 'digest')
            verifier = getattr(cipher_obj, 'verify')

            # ================= FILE WRITING PORTION =================
            # Read from the *file_path* and,
            # write to the *new_file* using _writer defined above.

            self._writer(self.file_path,
                         new_file,
                         crp,
                         flag,
                         nonce=nonce,
                         mac_function=mac_func,
                         mac_value=mac,
                         salt=self._salt, )

            # ================= VERIFICATION PORTION =================
            # Verify the file for integrity if the
            # current file is being decrypted.

            if not flag:
                try:
                    verifier(mac)

                except ValueError:

                    # Remove the incorrectly decrypted file
                    # and raise DataDecryptionError.

                    os.remove(new_file)

                    raise DecryptionError("Invalid password or tampered data.")

            # ========================================================

            # If remove set to True, delete the file
            # that is being worked upon.

            
        except Exception as err:
            raise err
        
        else:
            if remove:
                os.remove(self.file_path)
            
            return self

    def __repr__(self):
        password_check = True if self.password_hash is not None else False
        method_check = 'encrypt' if self._flag else 'not set' \
                        if self._flag is None else 'decrypt'

        return f'<{self.__class__.__name__}: method=`{method_check}`, ' \
               f'using-password={password_check}>'
     
