from Locker import encrypt, decrypt
from walker import walker, separator

def main_locker(*files, method, key):
  
  """
  This function is for the file locker. It will
  take any sort of drive paths as argument.
  
  The method takes *encrypt* or *decrypt* as Names.
  Evidently, the 'encrypt' encrypts the files with given *key*,
  and the *decrypt* does the reverse, provided that the key is
  correct.
  
  The passphrase must be very strong and must be of length of at least
  8 charecters. Or else, the program is going to shoot error message a you!
  """
  
  class PasswordLengthError(Exception):
    pass
  
  if len(key) < 8:
    raise LengthError(r'Length of passphrase is less than required (min. length is 8)')
  dirs, files = separator(*files)
  for d in dirs:
    for each_file in d:
      method(each_file, key)
    
  for file in files:
    method(file, key) 
    
