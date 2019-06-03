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
