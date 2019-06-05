import os

def walker(filepath):
  
  """
  This function recursively walks into a specified
  directory *filepath* and yeilds (i.e., creates generator
  object) which specifies the absolute path of the files
  The commented out part is for filtering out files with only
  targeted extensions.
  """
  
  path0 = os.path.normpath(filepath)
  path = os.path.abspath(path0)
  
  try:
    for (root, dirs, files) in os.walk(path):
      for file in files:
      # extn = os.path.splitext(file)[1]
      # if extn in extns
        target = os.path.join(root, file)
        yield target
  except Exception:
    pass


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
