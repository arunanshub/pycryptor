import os
import queue
from concurrent import futures
from functools import partial

from .walker import walker


def files_locker(*files,
                 password,
                 ext,
                 backend=None,
                 lock=True,
                 max_workers=None,
                 **kwargs):
    """
    This encrypts/decypts multiple files simultaneously by initiating
    a Process Pool. The `max_number` of process is `os.cpu_count() // 2`
    by default.

    This will support directory walkers.

    :param files: file paths to be used.
    :param password: bytes object of any length. (recommended length > 8)
    :param ext: Extension that will be used to check the file if it can be
                decrypted or not.
    :param kwargs: "all `kwargs` compatible with locker module.
    :return: dictionary showing which files were processed successfully.
    # TODO
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

                if each is None:
                    exhausted = True
                    break

                elif size_or_stat == 'FNF' or size_or_stat == 'INV':
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
            yield (path, 'FAIL')
        elif not error:
            yield (path, 'SUC')


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
            yield (each, 'FNF')


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
                    yield (each, 'INV')
            else:
                # these files were not found by `_to_paths`
                yield each
    # just simply return all the file paths
    else:
        yield from paths
