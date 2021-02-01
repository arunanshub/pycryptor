import itertools
import logging
import os
from concurrent import futures
from functools import partial

from pyflocker.ciphers import AES, exc
from pyflocker.ciphers.backends import Backends
from pyflocker.locker import locker

SUCCESS = 1 << 1
FAILURE = 1 << 2
INVALID = 1 << 3
FILE_NOT_FOUND = 1 << 4
FILE_EXISTS = 1 << 5
PERMISSION_ERROR = 1 << 6

logger = logging.getLogger(__name__)


# Fix the hanging of ProcessPoolExecutor
for i in list(Backends):
    AES.new(True, bytes(32), AES.MODE_GCM, bytes(16), backend=i)


def chunkify(iterable, n):
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
    thread_name_prefix="pycryptor",
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
        pool = futures.ProcessPoolExecutor(
            max_workers,
        )
        logger.debug("Built a processpool object %s", pool)
    except ImportError:
        pool = futures.ThreadPoolExecutor(
            max_workers, thread_name_prefix=thread_name_prefix
        )
        logger.debug("Built a threadpool object %s", pool)

    # TODO: Consider this: pool.map(func, files, chunksize=chunksize)
    with pool:
        logger.debug(f"Entered pool context successfully with {locking=}")

        f = partial(_mapper, ext=ext, locking=locking, f=_locker)

        for chunk in chunkify(files, chunksize):
            temp_res = [pool.submit(f, path=path) for path in chunk]
            yield from (f.result() for f in futures.as_completed(temp_res))

    logger.debug("Finished pool context.")


def _mapper(path, ext, locking, f):
    if not os.path.exists(path):
        return path, FILE_NOT_FOUND
    if locking and path.endswith(ext):
        return path, INVALID

    try:
        logger.debug(f"{path=} is valid. Submitting to function.")
        f(path)
        stat = SUCCESS
    except exc.DecryptionError:
        stat = FAILURE
    except FileExistsError:
        stat = FILE_EXISTS
    except (TypeError, IsADirectoryError):
        # header error when locking == False and path.endswith(ext)
        stat = INVALID
    except PermissionError:
        stat = PERMISSION_ERROR

    logger.debug(f"{path=} was processed with {stat=}")
    return path, stat
