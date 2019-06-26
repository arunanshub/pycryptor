import os

def separator(*files):
  
  """
  This function will take filepaths and sepatate and store in
  two different sets on the basis of their type (file or directory).
  
  Note: If it is a directory, it will return a generator object which will
        walk the directory.
        If the file (or directory) does not exist, it is simply ignored.
        
  Returns: Tuple of first part consisting a set of a directory walker,
           and second path consists of *file* set.
  """
  
  dir_set = set()
  file_set = set()
  for file in files:
    file = os.path.normpath(file)
    if os.path.exists(file):
      if os.path.isdir(file):
        wlk = walker(file)
        dir_set.add(wlk)
      
      if os.path.isfile(file):
        f_path = os.path.abspath(file)
        file_set.add(f_path)
    else:
      pass
  return dir_set, file_set
