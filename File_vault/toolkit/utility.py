from pkgutil import find_loader
import importlib

# colors for elements
color_primary = "#7d5fff"
color_primary_dark = "#3d3d3d"
color_accent_dark = "#4b4b4b"
color_success = "#32ff7e"
color_danger = "#ff4d4d"
color_warning = "#ffaf40"
color_info = "#18dcff"
color_white = "#ffffff"

# General messages for the App
aboutmsg = """Pycryptor v.{version}
Pycryptor is a portable app for encryption and
decryption of files. It is completely written in Python
and uses "AES-GCM" for encryption and decryption of files.

Features:
- Completely customisable
- Fully Open-Source
- No external dependencies needed
  and it supports multiple backends :)
- Fast file processing due to the use of threads

Also Available at: https://github.com/arunanshub/pycryptor"""


credits_ =( "Creators create...\n"
           "Pycryptor v.{version}\n"
           "\n"
           "Created with love by:\n"
           "1) Arunanshu Biswas (arunanshub)\n"
                "\tCryptographic File locking facilities\n"
                "\tMultithreading Capabilities\n"
                "\t... plus all backend\n"
                "\t(and GUI development)\n"
                "\n"
           "Also Available at: http://github.com/arunanshub/pycryptor")


help_msg = """Pycryptor v.{version}

Color codes:
- Green  : Successful operation
- Purple : Skipped files
- Yellow : Files not found
- Red    : Failed operation

Note:
Sometimes, if big files are given for encryption
(or decryption), Pycryptor stops responding.
This is NOT a bug, as Pycryptor continues the operation.
It would be fixed later due to some unavoidable reasons,
but other than that, everything is golden."""

config_help = """Help for Options > Configure:

    - Key length : Specify the key length.
        32 = AES-GCM-256
        24 = AES-GCM-192
        16 = AES-GCM-128

    - Extension : Extension to be used for encrypted files.
    
    - Backend : The backend module to be used by Pycryptor
                Using this without knowledge about backends
                used by Pycryptor may lead to problems."""


no_backend_error = ("Pycryptor needs a backend for encryption and "
                    "decryption, but it was not found. Please "
                    "configure your system properly.")
# ==============================================================
# Functions for getting backend defined here...

def backends():
    """
    Backend selector for efficient handling of things :)
    """

    x = {'Cryptodome': (True if find_loader('Cryptodome')
                        else False),
         'Crypto': (True if find_loader('Crypto')
                    and int(__import__('Crypto').__version__[0]) >= 3
                    else False),
         'cryptography': (True if find_loader('cryptography')
                          else False)}
    return x


def get_backend():
    """
    Returns the best backend (depending on system configuration).
    Assumes that backends (multiple or not) are present.

    This is used only once for app init purposes.
    """
    backends_ = backends()

    if all(backends_.values()):
        # favour cryptography as this is fast
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
    if backend == 'Cryptodome':
        exec('from .backends import pylocker as locker', globals())
    elif backend == 'cryptography':
        exec('from .backends import crylocker as locker', globals())
    elif backend == 'Crypto':
        exec('from .backends import pylocker as locker', globals())
    
    return locker
