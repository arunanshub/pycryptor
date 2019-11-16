
# pycryptor 
A short, sweet, PoC Python Ransomware (+A file vault for protecting the users files)
using Advanced Encryption Standards. The program uses 
[__AES-GCM__](https://en.wikipedia.org/wiki/Galois/Counter_Mode) for its work. 

There are two flavors of the program, one is a __File Vault__ and the other is an
effective multi-platform  __Python Ransomware__.

The `thread_locker` uses `concurrent.futures` thread pools for getting it's job done.

## Features

The python module `locker.py` uses [__AES-GCM__](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
for its work. By default, the key length is set to __256 bytes__.

The locker's speeds are very impressive. Also, the `cryptography` locker's speeds are greater
than `pycryptodome(x)` locker.

Encryption/Decryption speeds:

|File size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
|:-------:|:-------------------------:|:-------------------------:|
|  84MB   |         0.321843          |         0.313680          |
|  835MB  |         5.022431          |         4.948784          |

(all tested in Google Colab)

## On the face of dillema...

 - The folder `cryptography_locker` contains a ready-to-use locker,
   which employs the functionality provided by `cryptography` module
   
 - The folder `as_class` contains the same locker, but it is written as a class.

Encryption/Decryption speeds for this `cryptography_locker/locker.py` </br>

|File Size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
|:-------:|:-------------------------:|:-------------------------:|
|  85MB   |         0.220274          |         0.217195          |
|  858MB  |         5.068394          |         4.854502          |

(all tested in Google Colab)

## Before you use...

File encrypted with `cryptography` module's locker cannot be decrypted with
`pycryptodome(x)` module's locker and vice versa. Their implementation is very 
different from each other. 

Although I suggest you to use the `cryptography` locker. It is faster than it's 
`pycryptodome(x)` equivalent.

## A note on the ransomware...

__The ransomware provided is for educational purposes only. I take NO 
responsibilities for any misuse of the same. Although I am sure there won't
be any... 😁__
