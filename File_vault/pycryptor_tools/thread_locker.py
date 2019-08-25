import os
from collections import deque
from concurrent import futures
from queue import PriorityQueue

from pycryptor_tools.locker import locker, DecryptionError


def thread_locker(file_list, password, mode, **kwargs):
    """
    :param file_list: iterable having valid file paths
    :param password: bytes object of any length. (recommended length >8)
    :param mode: 'encrypt' or 'decrypt'
    :param kwargs: "all `kwargs` compatible with locker + max ons. of threads.
    :return: dictionary showing which files were processed successfully.
    """
    ext = kwargs.get('ext', '.0DAY')

    cpu_nos = kwargs.get('max_nos') or os.cpu_count()
    file_queue = PriorityQueue()
    future_states = deque()
    stats = {'FNF': deque(), 'FAIL': deque(), 'SUC': deque(), 'INV': deque()}
    files = iter(file_list)

    with futures.ThreadPoolExecutor(max_workers=cpu_nos) as exc:
        for file in files:
            try:
                if mode == 'encrypt':
                    if file.endswith(ext):
                        stats['INV'].append(file)
                    else:
                        file_queue.put_nowait((os.path.getsize(file), file))

                if mode == 'decrypt':
                    if not file.endswith(ext):
                        stats['INV'].append(file)
                    else:
                        file_queue.put_nowait((os.path.getsize(file), file))

            except FileNotFoundError:
                stats['FNF'].append(file)

        while not file_queue.empty():
            _, file = file_queue.get_nowait()
            future = exc.submit(locker, file, password, **kwargs)
            future_states.append((future, file))

        for (future, file) in future_states:
            error = future.exception()
            if isinstance(error, DecryptionError):
                stats['FAIL'].append(file)
            elif isinstance(error, RuntimeError):
                stats['FAIL'].append(file)
            elif not error:
                stats['SUC'].append(file)

    return stats
