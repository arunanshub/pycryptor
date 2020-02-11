import os
import queue
from concurrent import futures
from functools import partial

from .walker import walker

SUCCESS = 'SUC'
FAILURE = 'FAIL'
INVALID = 'INV'
FILE_NOT_FOUND = 'FNF'


def files_locker(*files,
                 password,
                 ext,
                 backend=None,
                 lock=True,
                 max_workers=None,
                 **kwargs):
    """
    This function encrypts or decrypts multiple files or directories
    simultaneously, thanks to `concurrent.futures.ProcessPoolExecutor`.

    For directories, a directory walker is used. `glob` module is not
    used intentionally, because it would have ignored the unusable
    files, and this function wouldn't have been able to report the unusable
    files.

    The maximum number of process spawned depends on the number of
    available cores on the system by default. It defaults to `cpu_count / 2`.
    Internally, PriorityQueue is used for selection of smallest file first,
    which is quick to encrypt or decrypt.

    :param files: any file or dir path.

    :param password: bytes object of any length. (recommended length > 8)

    :param ext: an extension that will be compared with the filenames
                to check if they can be used according to the mode
                (encrypt/decrypt).

    :param backend: A backend module to use.
                    Defaults to `crylocker`, which supports `cryptography`
                    module.
                    `pylocker` module uses `Cryptodome` or `Cryptodomex`.
                    Refer to backend modules for more information.

    :param kwargs: All the `kwargs` that are supported by `locker` module.

    :return:
        Iterable which yields `(filename, result)` tuple.
        The `result` can be among the following:

            `SUC`  : File was processed successfully.
            `FAIL` : File couldn't be processed correctly.
                    (most probably a failure in decryption caused by incorrect
                    password or invalid metadata. Refer to `locker` modules.)
            `INV`  : File was invalid because it cannot be used because it had
                    an unacceptable extension.
            `FNF`  : The path was not found on the system.

    """
    if not isinstance(password, bytes):
        raise TypeError("password must be a bytes object.")

    if backend is None:
        from .backends import crylocker as backend

    # some useful variables
    _cpu_count = max_workers or os.cpu_count()
    _locker = partial(backend.locker, password=password, ext=ext, **kwargs)

    with futures.ProcessPoolExecutor(_cpu_count) as exc:
        file_q = queue.PriorityQueue(_cpu_count**2)
        all_files = _check_ext(_to_paths(files), ext=ext, lock=lock)

        exhausted = False
        while not exhausted:
            fut = set()

            for i in range(file_q.maxsize):
                # put all the files in a limited amount
                each, size_or_stat = next(all_files, (None, None))

                # break out of the loop.
                if each is None:
                    exhausted = True
                    break
                elif size_or_stat == FILE_NOT_FOUND or size_or_stat == INVALID:
                    # yield invalid files.
                    yield (each, size_or_stat)
                else:
                    file_q.put_nowait((each, size_or_stat))

            try:
                # get all the files and add to fut set
                while True:
                    each, _ = file_q.get_nowait()
                    fut.add((exc.submit(_locker, each), each))
            except queue.Empty:
                pass

            yield from _categorize_by_error(fut, backend)


def _categorize_by_error(f, backend):
    """
    Yield the filepaths with their category (errors or success).
    """
    for future, path in f:
        error = future.exception()
        if isinstance(error, (RuntimeError, backend.DecryptionError)):
            yield (path, FAILURE)
        elif not error:
            yield (path, SUCCESS)


def _to_paths(files):
    """
    Yields paths by walking into directories.
    """
    isdir = os.path.isdir
    isfile = os.path.isfile
    exists = os.path.exists
    for each in set(files):
        if exists(each):
            if isdir(each):
                yield from walker(each, absolute=True)
            elif isfile(each):
                yield each
        else:
            yield (each, FILE_NOT_FOUND)


def _check_ext(paths, ext=None, lock=False):
    """
    Yield workable (file, size) pair;
    # TODO
    """
    if ext:
        # `ext` is the encrypted file's extension.
        if not lock:
            _check = lambda each, ext=ext: each.endswith(ext)
        else:
            _check = lambda each, ext=ext: not each.endswith(ext)
        getsize = os.path.getsize
        # iterate over the file-paths
        for each in paths:
            if len(each) != 2:
                if _check(each):
                    yield (each, getsize(each))
                else:
                    # files found were invalid.
                    yield (each, INVALID)
            else:
                # these files were not found by `_to_paths`
                yield each
    # just simply return all the file paths
    else:
        yield from paths
