import os


def walker(path, exts=None, *, absolute=False, lock=False):
    """
    This function recursively walks into a specified
    directory *file_path* and yields (i.e., creates generator
    object) file paths in the directory.

    `exts` is an iterable with all extensions to be included
    in `walker`'s output. If `exts` is specified, then the
    files which ends with it are only yielded.
    - If `ignore_ext` is set to True, the any extension in `exts` would
      be ignored, i.e. files not ending with `exts` would be yielded.

    If `absolute` argument is set to `True`, then the absolute
    path of the files are yielded.
    """
    if absolute:
        path = os.path.abspath(path)

    if not lock:
        _check_ext = lambda each, exts=exts: os.path.splitext(each)[1] in exts
    else:
        _check_ext = lambda each, exts=exts: not os.path.splitext(each)[
            1] in exts

    for (root, _, files) in os.walk(path):
        for each in files:
            if exts is not None:
                if _check_ext(each):
                    yield os.path.join(root, each)
            else:
                yield os.path.join(root, each)
