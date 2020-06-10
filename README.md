
# pycryptor

File vault GUI wrriten in Python using Tkinter which uses AES-GCM for encryption
and decryption.


## Getting Started

Run the File Vault by launching the `Pycryptor.pyw`.


## The `locker` modules

**WARNING: The locker modules will be deprecated in favour of a better file
locking API. This also means, the file header format that are used to store
the metadata will be changed for a newer format.**


**`pylocker.py`** uses the backend [Pycryptodome(x)][6] and 
**`crylocker.py`** uses the backend [cryptography][7].
Find the locker module's README [here][3].

**The class based `locker` has been removed.**


## Where is the ransomware?

The ransomware has been removed due to difficulty in maintenance
(and also due to the fact that better implementations are available)  
But it would probably be released in a separate repo.


[2]: <File_vault/README.md#pycryptor---the-file-vault>
[3]: <File_vault/toolkit/backends/README.md#the-core>
[4]: <File_vault/toolkit/backends/pylocker.py>
[5]: <File_vault/toolkit/backends/crylocker.py>
[6]: <https://github.com/Legrandin/pycryptodome#pycryptodome>
[7]: <https://github.com/pyca/cryptography#pycacryptography>
