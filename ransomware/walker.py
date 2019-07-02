import os


# define an extension list here if you want to filter
# out only selected extensions

def walker(file_path):
    """
    This function recursively walks into a specified
    directory *file_path* and yields (i.e., creates generator
    object) which specifies the absolute path of the files
    The commented out part is for filtering out files with only
    targeted extensions.
    """

    path0 = os.path.normpath(file_path)
    path = os.path.abspath(path0)

    try:
        for (root, dirs, files) in os.walk(path):
            for file in files:
                # extn = os.path.splitext(file)[1]
                # if extn in extension_list

                # Indent the two lines if you want to filter out
                target = os.path.join(root, file)
                yield target
    except Exception:
        pass
