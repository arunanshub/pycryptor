import os


def walker(path, exts=None, *, absolute=False):
    """
    This function recursively walks into a specified
    directory *file_path* and yields (i.e., creates generator
    object) which specifies the absolute path of the files

    `exts` is an iterable with all extensions to be included
    in `walker`'s output. If `exts` is specified, then the
    files which ends with it are only yielded.

    If `absolute` argument is set to `True`, then the absolute
    path of the files are yielded.
    """
    if absolute:
        path = os.path.abspath(path)
    for (root, _, files) in os.walk(path):
        for each in files:
            if exts is not None:
                if os.path.splitext(each)[1] in exts:
                    yield os.path.join(root, each)
            else:
                yield os.path.join(root, each)
