# pycryptor 
A short, sweet, PoC Python Ransomware (+**A file vault for protecting the users files**) using Advanced Encryption Standards. 
The program uses the __AES-GCM-256__ for its work.

There are two flavors of the program, one is a simple __File Encryptor__ and the other is a simple and 
effective multiplatform  __Python Ransomware__. The __File Vault__ was actually a school project, 
but the idea of ransomware came to me because of the procedure I was using for encrypting the files.

The `thread_locker` uses `concurrent.futures` thread pools for getting it's job done.


## Features

 - Uses AES-GCM-256 for encryption and decryption.
 - File is verified after decryption.
 - Fast encryption and decryption speeds.

|File size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
|:-------:|:-------------------------:|:-------------------------:|
|  84MB   |         0.321843          |         0.313680          |
|  835MB  |         5.022431          |         4.948784          |


## Additional Note

 - A seperate folder named as **`cryptography_locker`** contains the
   same Locker file, but this one uses cryptography module instead. You
   can replace the **original** `Locker.py` with this `Locker.py`
   instead, it won't harm the functionality of the program.
   
 - __Encryption/Decryption speeds for this `Locker.py`__

|File Size|Encryption Speed (in secs.)|Decryption Speed (in secs.)|
|:-------:|:-------------------------:|:-------------------------:|
|  85MB   |         0.220274          |         0.217195          |
|  858MB  |         5.068394          |         4.854502          |

 - __`as-Class`__ folder contains both the Lockers, but they are implemented as a class.


## Warning note for both the Lockers–Read Me First

 - __Please note that the file encrypted with pycryptodome/Locker.py won't
   be decrypted by this cryptography/Locker.py and vice versa. This is
   due to the way pycryptodome and cryptography module works.__

 - __Encrypt (or decrypt) the files with appropriate `Locker.py` *only*.
   If you fail to do do so, unforseeable problems may destroy your
   program logic.__

---

And as a final word of caution: 
Cryptography is a very powerful yet sensitive thing. <br />
If used properly, you get good results, but if you fail to do so, remember:

### (Quoted directly from `cryptography/hazmat/__init__.py`)

> __You should ONLY use it if you're 100% absolutely sure that you know  <br />
> what you're doing because this program is full of land mines, dragons, <br />
> and dinosaurs with laser guns.__

## Objections–please follow this
The Ransomware provided is meant only for educational purposes and __IS NOT MEANT FOR ANY MALICIOUS PURPOSES__. 
I will not be responsible for any sort of damage caused to anyone's property.
