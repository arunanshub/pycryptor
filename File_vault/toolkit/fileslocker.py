import os
from collections import deque
from concurrent import futures
from queue import PriorityQueue


def files_locker(file_list, password, mode, backend, **kwargs):
    """
    This encrypts/decypts multiple files simultaneously by initiating
    a Process Pool. The `max_number` of process is `os.cpu_count() // 2`
    by default.

    :param file_list: iterable having valid file paths
    :param password: bytes object of any length. (recommended length > 8)
    :param mode: 'encrypt' or 'decrypt'
    :param backend: the locker module to use.
    :param kwargs: "all `kwargs` compatible with locker + max nos. of threads.
    :return: dictionary showing which files were processed successfully.
    """
    if not isinstance(password, bytes):
        raise TypeError("password must be a bytes object.")
    ext = kwargs.get('ext', '.0DAY')

    cpu_nos = kwargs.get('max_nos') or (os.cpu_count() // 2)
    file_queue = PriorityQueue()
    future_states = deque()
    stats = {'FNF': deque(), 'FAIL': deque(), 'SUC': [], 'INV': []}
    files = iter(file_list)

    with futures.ProcessPoolExecutor(max_workers=cpu_nos) as exc:
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
            future = exc.submit(backend.locker, file, password, **kwargs)
            future_states.append((future, file))

        for (future, file) in future_states:
            error = future.exception()
            if isinstance(error, backend.DecryptionError):
                stats['FAIL'].append(file)
            elif isinstance(error, RuntimeError):
                stats['FAIL'].append(file)
            elif not error:
                stats['SUC'].append(file)

    return stats
