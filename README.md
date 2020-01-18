
# pycryptor

A short, sweet, PoC Python Ransomware (+A file vault for protecting the users
 files) using Advanced Encryption Standards. The program uses  [__AES-GCM__][1] 
 for its work. <br>
There are two flavors of the program, one is a [__File Vault__][2] and the other
is an effective multi-platform  __Python Ransomware__(and it is incomplete).

## Getting Started

This repo consists of two prominent folders. One is the `File_vault` and 
`ransomware`. 

The `File_vault` is a program which can be used to encrypt and decrypt 
your files safely. Read about it [here][2].

The `ransomware` is a ransomware (you guessed it!), written in Python. It is 
under development and, I hope a better thing would be released. 
For now, it is just a base of the program.

## The `locker` modules

The `locker` module can be used in a standalone way in other applications. 
Initially, it was created to provide the file locking/unlocking provision to the 
app, but eventually it became mature enough to be used as a standalone API.

Here, **`pylocker.py`** uses the backend [Pycryptodome(x)][6] and 
**`crylocker.py`** uses the backend [cryptography][7]. Both the 
lockers are compatible with each other, which is a good news!

Find the locker module's README [here][3].

A class based `locker` is also there, which is **just an experiment**. 
Learn more about it [here][8].

### Performance of the lockers

The locker's speeds are very impressive. Also, the `crylocker.py` 
speeds are greater than `pylocker.py`, which can be found 
in [Pycryptor's backend][3].

- Encryption/Decryption speeds for [`pylocker.py`][4]:

  |File size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
  |:-------:|:-------------------------:|:-------------------------:|
  |  84MB   |         0.321843          |         0.313680          |
  |  835MB  |         5.022431          |         4.948784          |

- Encryption/Decryption speeds for [`crylocker.py`][5]:

  |File Size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
  |:-------:|:-------------------------:|:-------------------------:|
  |  85MB   |         0.220274          |         0.217195          |
  |  858MB  |         5.068394          |         4.854502          |

(all tested in Google Colab)

## Before using the ransomware

__The ransomware provided is for educational purposes only. 
I take NO responsibilities for any misuse of the same. Although 
I am sure there won't be any... 😁__


[1]: <https://en.wikipedia.org/wiki/Galois/Counter_Mode>
[2]: <File_vault/README.md#pycryptor---the-file-vault>
[3]: <File_vault/toolkit/backends/README.md#the-core>
[4]: <File_vault/toolkit/backends/pylocker.py>
[5]: <File_vault/toolkit/backends/crylocker.py>
[6]: <https://github.com/Legrandin/pycryptodome#pycryptodome>
[7]: <https://github.com/pyca/cryptography#pycacryptography>
[8]: <as-Class/README.md#locker-as-class>
