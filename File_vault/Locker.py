#locker v3
import hashlib
import os, stat

from Cryptodome.Cipher import AES
from Cryptodome import Random
from struct import pack, unpack, calcsize


NONCESIZE = 12
MACLEN = 16
BLOCKSIZE = 64*1024
EXT = '.0DAY'

class DataDecryptionError(ValueError):
    pass

def _writer(filepath, newfile, method, flag, **kargs):
  """
  This function takes care of readingfrom the file - *filepath*
  and writing to the new file *newfile* with the provided method by 
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
  """
  
    
  if kargs:
      nonce = kargs['nonce']
      macfunc = kargs['mac']
  
  os.chmod(filepath, stat.S_IRWXU)   
  with open(filepath, 'rb') as infile:
      with open(newfile, 'wb+') as outfile:
          while True:
              part = infile.read(BLOCKSIZE)
              if not part:
                  break
              new = method(part)
              outfile.write(new)
          
          # If the file is being encrypted, write the
          # *mac* tag and *nonce* value to the *newfile*
          if flag:
              mac = macfunc()
              form = '<{}s{}s'.format(NONCESIZE, MACLEN)
              nonce_mac = pack(form, nonce, mac)
              outfile.write(nonce_mac)
                
def locker(filepath, password, remove=True):
  """
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

          format_ = '<{}s{}s'.format(NONCESIZE, MACLEN)
          format_size = calcsize(format_)
          
          # Read the nonce and mac values
          with open(filepath, 'rb+') as f:
              f.seek(-format_size, 2)
              nonce, mac = unpack(format_, f.read())
          
          # Remove the mac and nonce from the encrypted file
          orig_file_size = os.path.getsize(filepath) - format_size
          os.truncate(filepath, orig_file_size)
          newfile = os.path.splitext(filepath)[0]
      
      # The file is being encrypted.
      else:
          method = 'encrypt'
          flag = True
          nonce = os.urandom(12)
          newfile = filepath + EXT

      # A cipher object will take care of the all
      # the required mactag and verification.
      try:
          key = hashlib.sha3_256(password.encode()).digest()
      except AttributeError:
          # password given by the user is in binary format
          key = hashlib.sha3_256(password).digest()

      cipher_obj = AES.new(key, AES.MODE_GCM, nonce)

      crp = getattr(cipher_obj, method)
      macfunc = getattr(cipher_obj, 'digest')
      verifier = getattr(cipher_obj, 'verify')

      # read from the *filepath* and,
      # write to the *newfile*
      _writer(filepath, newfile, crp, flag, nonce=nonce, mac=macfunc)

      # If remove set to True, delete the file 
      # that is being worked upon.
      if remove:
        os.remove(filepath)
        
      # Verify the file for integrity if the
      # current file is being decrypted.
      if not flag:
        try:
            verifier(mac)

        except ValueError:

            # If decryption fails, revert back to the original
            # condition, i.e., Add the *nonce* and *mac* back to
            # the encrypted file.
            with open(filepath, 'rb+') as f:
                f.seek(0, 2)
                f.write(pack(format_, nonce, mac))

            # Remove the incorrectly decrypted file 
            # and raise DataDecryptionError.
            newfile = os.path.splitext(filepath)[0]
            os.remove(newfile)
            
            raise DataDecryptionError('Either Password is incorrect or Encrypted Data has been tampered.')

  except FileNotFoundError:   
    pass
  
  except IsADirectoryError:
    pass
