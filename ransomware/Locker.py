#!/usr/bin/python
# -*- coding: utf-8 -*-
# locker v3.1

import hashlib
import os
import stat

from struct import pack, unpack, calcsize
from Cryptodome.Cipher import AES

NONCESIZE = 12
MACLEN = 16
BLOCKSIZE = 64 * 1024
EXT = '.0DAY'


class DecryptionError(ValueError):

    pass


def _writer(filepath, newfile, method, flag, **kargs):
    """Facilates file writing
  This function takes care of reading from the file - *filepath*
  and writing to the new file - *newfile* with the provided method by
  looping through each line of the filepath of fixed length, specified by
  BLOCK_SIZE in global namespace.
  
    Usage
   -------
  filepath = File to be written on.
  
   newfile = Name of the encrypted/decrypted file to written upon.
  
    method = The way in which the file must be overwritten.
             (encrypt or decrypt)
  
      flag = This is to identify if the method being used is
             for encryption or decryption. 
             
             If the *flag* is *True* then the *nonce* value 
             and a *mac* tag function are accepted.
             If the *flag* is *False*, *nonce* value and a
             previously read *mac* value are accepted.
  """

    if kargs:
        nonce = kargs['nonce']
        mac_func = kargs['mac_function']
        mac_val = kargs['mac_value']

    if os.path.exists(newfile):
        os.chmod(newfile, stat.S_IRWXU)
        os.remove(newfile)
        
    os.chmod(filepath, stat.S_IRWXU)
    with open(filepath, 'rb+') as infile:
        with open(newfile, 'wb+') as outfile:
            while True:
                part = infile.read(BLOCKSIZE)
                if not part:
                    break
                new = method(part)
                outfile.write(new)

          # If the file is being encrypted, generate and
          # write the *mac* tag and *nonce* value to the *newfile*.

            if flag:
              # Generating the *mac* tag after encryption.
                derived_mac_val = mac_func()

                nonce_mac = pack('<{}s{}s'.format(NONCESIZE, MACLEN),
                                 nonce, derived_mac_val)
                outfile.write(nonce_mac)

          # If the file is being decrypted, put the *nonce* 
          # and recieved *mac* value back into the file to 
          # restore the previous condition of the encrypted file.

            if not flag:
                infile.seek(0, 2)
                infile.write(pack('<{}s{}s'.format(NONCESIZE, MACLEN),
                               nonce, mac_val))

def locker(filepath, password, remove=True):
    """Provides file locking/unlocking mechanism
  This function either encrypts or decrypts the file - *filepath*.
  Encryption or decryption depends upon the file's extension.
  The user's encryption or decryption task is almost automated since
  *encryption* or *decryption* is determined by the file's extension.
  
  Added:
      After the *filepath* decryption, decrypted file's verification
      is done. If it fails, either the Password is incorrect or the
      encrypted data was supposedly tampered with.
  
    Usage
   -------
   filepath = File to be written on.
        
   password = Key to be used for encryption/decryption.
              - Raises DataDecryptionError if *Password* is incorrect
                or Encrypted data has been tampered with.
   
     remove = If set to True, the the file that is being
              encrypted or decrypted will be removed.
              (Default: True).
  """

    try:

      # The file is being decrypted

        if filepath.endswith(EXT):
            method = 'decrypt'
            flag = False

          # Read the *nonce* and *mac* values.
          # Please note that we are recieving the *nonce*
          # and *mac* values.

            with open(filepath, 'rb+') as f:
                f.seek(-(NONCESIZE + MACLEN), 2)
                (nonce, mac) = unpack('<{}s{}s'.format(NONCESIZE, MACLEN),
                                      f.read())

          # Remove the *mac* and *nonce* from the encrypted file.
          # If not removed, Incorrect decryption will occur.

            orig_file_size = os.path.getsize(filepath) - (NONCESIZE + MACLEN)
            os.truncate(filepath, orig_file_size)
            newfile = os.path.splitext(filepath)[0]

        else:
            
          # The file is being encrypted.

            method = 'encrypt'
            flag = True
            newfile = filepath + EXT

          # Generate a *nonce* and set the mac to None,
          # As the *mac* ****will not be recieved*** this time 
          # but it will be generated after encryption.
          #
          # Generation will take place in _writer(...)
            nonce = os.urandom(12)
            mac = None
            
        key = hashlib.sha3_256(password).digest()

      ############## CIPHER GENERATION PORTION #############
      # A cipher object will take care of the all
      # the required mactag and verification.
      # AES-GCM-256 chosen for security and authentication

        cipher_obj = AES.new(key, AES.MODE_GCM, nonce)
        crp = getattr(cipher_obj, method)
        macfunc = getattr(cipher_obj, 'digest')
        verifier = getattr(cipher_obj, 'verify')

      ############## FILE WRITING PORTION ###################
      # Read from the *filepath* and,
      # write to the *newfile* using _writer defined above.

        _writer(filepath,
                newfile,
                crp,
                flag,
                nonce=nonce,
                mac_function=macfunc,
                mac_value=mac,)

      ################# VERIFICATION PORION ##################
      # Verify the file for integrity if the
      # current file is being decrypted.

        if not flag:
            try:
                verifier(mac)

            except ValueError:

              # Remove the incorrectly decrypted file
              # and raise DataDecryptionError.

                os.remove(newfile)
                raise DecryptionError("Either Password is incorrect or "
                                  "Encrypted Data has been tampered.")

      #########################################################

      # If remove set to True, delete the file
      # that is being worked upon.

        if remove:
            os.remove(filepath)

    except FileNotFoundError:
        
        pass
    except IsADirectoryError:
        
        pass
