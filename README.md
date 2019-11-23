
# pycryptor 

A short, sweet, PoC Python Ransomware (+A file vault for protecting the users files)
using Advanced Encryption Standards. The program uses 
[__AES-GCM__][1] for its work. 

There are two flavors of the program, one is a [__File Vault__][2] and the other is an
effective multi-platform  __Python Ransomware__.

The `thread_locker` uses `concurrent.futures` thread pools for getting it's job done.

## Features

The python module `locker.py` uses [__AES-GCM__][1]
for its work. By default, the key length is set to __256 bits__.

The locker's speeds are very impressive. Also, the `cryptography` locker's speeds are greater
than `pycryptodome(x)` locker, which can be found in [Pycryptor's backend][3]




## A word about the lockers...

The `locker` module can be used in a standalone way in other applications. Initially, it was created to provide the file locking/unlocking provision to the app, but eventually it became mature enough to be used as a standalone API.

Here, **`pylocker.py`** uses the backend [Pycryptodome(x)][6] and **`crylocker.py`** uses the backend [cryptography][7]

Find the module's README [here][3].

How fast are the lockers?
---

Encryption/Decryption speeds for [`pylocker.py`][4]:

|File size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
|:-------:|:-------------------------:|:-------------------------:|
|  84MB   |         0.321843          |         0.313680          |
|  835MB  |         5.022431          |         4.948784          |

---

Encryption/Decryption speeds for [`crylocker.py`][5]:

|File Size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
|:-------:|:-------------------------:|:-------------------------:|
|  85MB   |         0.220274          |         0.217195          |
|  858MB  |         5.068394          |         4.854502          |

(all tested in Google Colab)

## Before you use...

File encrypted with [`crylocker.py`][5] cannot be decrypted with
[`pylocker.py`][4] module's locker and vice versa. Their implementation is very different from each other. 

Although I suggest you to use the `crylocker.py`. It is faster than `pylocker.py`.

## A note on the ransomware...

__The ransomware provided is for educational purposes only. I take NO 
responsibilities for any misuse of the same. Although I am sure there won't
be any... 😁__


[1]: <https://en.wikipedia.org/wiki/Galois/Counter_Mode>
[2]: <File_vault/README.md>
[3]: <File_vault/toolkit/backends/README.md>
[4]: <File_vault/toolkit/backends/pylocker.py>
[5]: <File_vault/toolkit/backends/crylocker.py>
[6]: <https://github.com/Legrandin/pycryptodome#pycryptodome>
[7]: <https://github.com/pyca/cryptography#pycacryptography>

