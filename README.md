# pycryptor
A short, sweet, PoC Python Ransomware (+*A file vault for protecting the users files*) using Advanced Encryption Standards. The program uses the AES-GCM-256 for its work.

There are two flavors of the program, one is a simple *```File Encryptor```* and the other is a simple and effective multiplatform ```Python Ransomware```. The **File Vault** was actually a school project, but the idea of ransomware came to me because of the procedure I was using for encrypting the files.

Atleast, for now, the encryptor and decryptor functions doesn't use the ```threading/multiprocessing/asyncio``` modules' benifits. But work is under progress, so it is *hoped that all will be great under the hood...*

## Features:
  - Uses AES-GCM-256 for encryption and decryption.
  - File is verified after decryption.
  - **Encryption and decryption speeds are quite fast.**
      
      | File size   | Encryption Speed (in secs.)   |  Decryption Speed (in secs.)  |
      |:-----------:|:-----------------------------:|:-----------------------------:|
      |    84MB     |           0.321843            |           0.313680            |
      |   835MB     |           5.022431            |           4.948784            |
    

## Objections: 
  - **The Ransomware is meant only for educational purposes and IS NOT MEANT FOR ANY MALICIOUS PURPOSES.**
    **I will not be responsible for any sort of damage caused to anyone's property.**
