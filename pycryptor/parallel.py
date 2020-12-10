import os
import itertools
from concurrent import futures
from functools import partial
from pyflocker.locker import locker
from pyflocker.ciphers import exc

SUCCESS = 1 << 1
FAILURE = 1 << 2
INVALID = 1 << 3
FILE_NOT_FOUND = 1 << 4


def chunkify(iterable, n, fillvalue=None):
    """Collect data into fixed-length chunks or blocks.

    Code adapted from more-itertools.
    """

    def take(iterable, n):
        return tuple(itertools.islice(iterable, n))

    return iter(partial(take, iter(iterable), n), ())


def files_locker(
    *files,
    password,
    ext,
    locking,
    backend=None,
    max_workers=None,
    chunksize=16,
    **kwargs,
):
    """Encrypt or decrypt multiple files concurrently.

    # TODO: Fill docs.
    """
    if not isinstance(password, bytes):
        raise TypeError("password must be a bytes object.")

    # some useful variables
    max_workers = max_workers or os.cpu_count()
    _locker = partial(
        locker,
        password=password,
        backend=backend,
        ext=ext,
        locking=locking,
        **kwargs,
    )

    try:
        pool = futures.ProcessPoolExecutor(max_workers // 2)
    except ImportError:  # android does not support multiprocessing module
        pool = futures.ThreadPoolExecutor(max_workers)

    results = []
    # TODO: Consider this: pool.map(func, files, chunksize=chunksize)
    with pool:
        for c in chunkify(set(files), chunksize):
            results.append(
                pool.map(
                    partial(_mapper, ext=ext, locking=locking, f=_locker,), c,
                ),
            )

        for r in results:
            yield from r


def _mapper(path, ext, locking, f):
    if not os.path.exists(path):
        return path, FILE_NOT_FOUND
    if locking and path.endswith(ext):
        return path, INVALID

    try:
        f(path)
        return path, SUCCESS
    except exc.DecryptionError:
        return path, FAILURE
    except (TypeError, IsADirectoryError):
        # header error when locking == False and path.endswith(ext)
        return path, INVALID
