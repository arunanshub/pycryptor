# pycryptor
A short, sweet, PoC Python Ransomware (+*A file vault for protecting the users files*) using Advanced Encryption Standards. The program uses the AES-GCM-256 for its work.

There are two flavors of the program, one is a simple *```File Encryptor```* and the other is a simple and effective multiplatform ```Python Ransomware```. The **File Vault** was actually a school project, but the idea of ransomware came to me because of the procedure I was using for encrypting the files.

Atleast, for now, the encryptor and decryptor functions doesn't use the ```threading/multiprocessing/asyncio``` modules' benifits. But work is under progress, so it is *hoped that all will be great under the hood...*

---
> __Work for the `File vault` and `Ransomware` is still under progress__

## Features:
  - Uses AES-GCM-256 for encryption and decryption.
  - File is verified after decryption.
  - ***Encryption and decryption speeds are quite fast.***
      
      | File size   | Encryption Speed (in secs.)   |  Decryption Speed (in secs.)  |
      |:-----------:|:-----------------------------:|:-----------------------------:|
      |    84MB     |           0.321843            |           0.313680            |
      |   835MB     |           5.022431            |           4.948784            |
    

## Additional note:
  - A seperate folder named as **``cryptography_locker``** contains the same Locker file,
    but this one uses cryptography module instead. You can replace the **original
    ``Locker.py``** with this ``Locker.py`` instead, it won't harm the functionality of the
    program.
    
  P.S: The encryption and decryption speed may increase if this file is used. 
       I experimented with the same in Google Colab (as all the other files were done), 
       where I got very fine speeds. But it may vary from system to system.
   
  + ***Encryption/Decryption speeds for this Locker.py***
   
     | File Size | Encryption Speed (in secs.) | Decryption Speed (in secs.) |
     |:---------:|:---------------------------:|:---------------------------:|
     |    85MB   |          0.220274           |          0.217195           |
     |   858MB   |          5.068394           |          4.854502           |
     
   
 ### Warning note for both the lockers (Read this first before using the Locker(s)):
   
   + **Please note that the file encrypted with pycryptodome/Locker.py won't be decrypted by this 
       cryptography/Locker.py and vice versa. This is due to the way pycryptodome and cryptography module works.**
   
   +   Encrypt (or decrypt) the files with appropriate ```Locker.py``` *only*. If you fail to do 
       do so, unforseeable problems may destroy your program logic
       
---
  
  And as a final word of caution: 
   Cryptography is a very powerful yet sensitive thing. If used properly, you get good
   results, but if you fail to do so, remember: 
   
  #### (Quoted directly from `cryptography/hazmat/__init__.py`)
> "**You should ONLY use it if you're 100% absolutely sure that you know what you're doing 
  because this program is full of land mines, dragons, and dinosaurs with laser guns.**"

       
  

## Objections (please follow this): 
  - **The Ransomware provided is meant only for educational purposes and IS NOT MEANT FOR ANY MALICIOUS PURPOSES.**
    **I will not be responsible for any sort of damage caused to anyone's property.**
