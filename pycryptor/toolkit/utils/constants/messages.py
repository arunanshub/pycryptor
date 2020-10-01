# General messages for the App
aboutmsg = """Pycryptor v.{version}
Pycryptor is a portable app for encryption and
decryption of files. It is completely written
in Python and uses "AES-GCM" for its working.

Features:
- Completely customisable
- Fully Open-Source
- No external dependencies needed
  and it supports multiple backends :)
- Fast file processing due to the use of threads

Also Available at: https://github.com/arunanshub/pycryptor"""

credits_ = """Creators create...
Pycryptor v.{version}

Created with love by:
1) Arunanshu Biswas (arunanshub)
Cryptographic File locking facilities
Multithreading Capabilities
... plus all backend
(and GUI development)

Also Available at: http://github.com/arunanshub/pycryptor
"""

help_msg = """Pycryptor v.{version}

Color codes:
- Green  : Successful operation
- Purple : Skipped files
- Yellow : Files not found
- Red    : Failed operation
"""

config_help = """Help for Options > Configure:

    - Key length : Specify the key length.
        32 = AES-GCM-256
        24 = AES-GCM-192
        16 = AES-GCM-128

    - Extension : Extension to be used for encrypted files.

    - Backend : The backend module to be used by Pycryptor
                Using this without knowledge about backends
                used by Pycryptor may lead to problems.
"""

waitbox_msg = (
    "Please wait while your files are being {method}ed...\n"
    "Exiting the app while it is running may result in\n"
    "data corruption."
)

no_backend_error = (
    "Pycryptor needs a backend for encryption and "
    "decryption, but it was not found. Please "
    "configure your system properly."
)
