"""
All the functions required for the app to find the backends
are defined here.
"""

from pkgutil import find_loader


def backends():
    """
    Backend selector for efficient handling of things :)
    """
    x = {
        'Cryptodome': (True if find_loader('Cryptodome') else False),
        'Crypto':
        (True if find_loader('Crypto')
         and int(__import__('Crypto').__version__[0]) >= 3 else False),
        'cryptography': (True if find_loader('cryptography') else False)
    }
    return x


def get_backend():
    """
    Returns the best backend (depending on system configuration).
    Assumes that backends (multiple or not) are present.

    This is used only once for app init purposes.
    """
    backends_ = backends()

    if all(backends_.values()):
        # favour cryptography as this is faster
        return 'cryptography'

    elif not all(backends_.values()) and backends_['cryptography']:
        return 'cryptography'
    elif not all(backends_.values()) and backends_['Cryptodome']:
        return 'Cryptodome'
    else:
        return 'Crypto'


def change_backend(backend):
    """
    Backend changing mechanism.
    WARNING: too complex (but this works)!!

    The `locker` variable is the variable of our interest.

    But when the user wants to change their backend, we must
    allow them to do so.
    For this, we must change the locker variable to point at the
    appropriate backend (here `crylocker` or `pylocker`)

    """
    if backend == 'Cryptodome' or backend == 'Crypto':
        from ..backends import pylocker as locker
    elif backend == 'cryptography':
        from ..backends import crylocker as locker
    else:
        raise NotImplementedError
    return locker
