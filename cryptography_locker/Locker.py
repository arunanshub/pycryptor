#!/usr/bin/python
# -*- coding: utf-8 -*-
# Same Locker, but uses cryptography module instead...
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


import os, stat
import hashlib

from functools import partial
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


NONCE_SIZE = 12
MAC_LEN = 16
BLOCK_SIZE = 64 * 1024

EXT = '.TXT'


def _writer(filepath, newfile, method, flag, **kargs):
  """Facilates reading/writing to file.
  This function facilates reading from *filepath* and writing to
  *newfile* with the provided method by looping through each line 
  of the filepath of fixed length, specified by BLOCK_SIZE in global 
  namespace.
  
    Usage
   -------
  filepath = File to be written on.
  
   newfile = Name of the encrypted/decrypted file to written upon.
  
    method = The way in which the file must be overwritten.
             (encrypt or decrypt)
  
      flag = This is to identify if the method being used is
             for encryption or decryption. 
             
             If the *flag* is *True* then the *nonce* value 
             is written to the end of the *newfile*.
             
             If the *flag* is *False*, then the *nonce* is written to
             *filepath*.
  """
  
  if kargs:
    nonce = kargs['nonce']
    
  
  if not flag:
    global BLOCK_SIZE
    BLOCK_SIZE = BLOCK_SIZE + 16
  
  os.chmod(filepath, stat.S_IRWXU)
  with open(filepath, 'rb+') as infile:
    with open(newfile, 'wb+') as outfile:
      
      while True:
        part = infile.read(BLOCK_SIZE)
        if not part:
          break
        
        try:
          outfile.write(method(data=part))
        
      # This is raised when the file is being decrypted.
      
        except InvalidTag as err:
        # Write the nonce back into the encrypted file,
        # and raise Error
        
          infile.seek(0, 2)
          infile.write(nonce)
          raise err
      
    # Write the nonce into the *newfile* for future use.
      
      if flag:
        outfile.write(nonce)
    
    # Write the nonce to the *filepath* to restore the
    # original file condition
    
      if not flag:
        infile.seek(0, 2)
        infile.write(nonce)


def locker(filepath, password, remove=True):
  """Provides file locking/unlocking mechanism
  This function either encrypts or decrypts the file - *filepath*.
  Encryption or decryption depends upon the file's extension.
  The user's encryption or decryption task is almost automated since
  *encryption* or *decryption* is determined by the file's extension.
  
  
    Usage
   -------
   filepath = File to be written on.
        
   password = Key to be used for encryption/decryption.
   
     remove = If set to True, the the file that is being
              encrypted or decrypted will be removed.
              (Default: True).
  """
  
# The file is being decrypted
  try:
    if filepath.endswith(EXT):
      method = 'decrypt'
      flag = False
      newfile = os.path.splitext(filepath)[0]

    # Retreive the nonce and remove it from the
    # encrypted file

      with open(filepath, 'rb+') as f:
        f.seek(-NONCE_SIZE, 2)
        nonce = f.read()

      origsize = os.path.getsize(filepath) - NONCE_SIZE
      os.truncate(filepath, origsize)

  # The file is being encrypted
    else:
      method = 'encrypt'
      flag = True
      newfile = filepath + EXT

      nonce = os.urandom(NONCE_SIZE)

  # Create a cipher with  the required method   
    
    key = hashlib.sha3_256(password).digest()
    cipher = getattr(AESGCM(key), method)

  # Create a partial function with default values.
    
    crp = partial(cipher, nonce=nonce, associated_data=None)

  # Read from *filepath* and write to the *newfile*
    _writer(filepath, 
            newfile,
            crp,
            flag,
           nonce=nonce,)

    if remove:
      os.remove(filepath)
  
  except Exception as err:
    raise err
