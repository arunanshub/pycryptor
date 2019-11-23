

# Pycryptor - The File Vault

A pure Python file vault, backed by the powerful cryptographic libraries, namely 
[`Pycryptodome(x)`][1] and [`cryptography`][2]. Inspired by the other cryptographic 
file locking apps on the internet today, this app was born to serve the same purpose, although faster and in and Open-source manner :)


## Features

This app supports both the libraries, and has a very fast operating file locker 
module, which is kept in [`toolkit/backends`][3]. 

The app has been designed in such a way that it is easy for the user to modify
and incorporate it in their own projects. Feel free to test it and provide feedback 
to me. This would help me to improve this app in the long run.


## Future plans for the App

 - [x] Add multiple backend support for the app
 - [ ] Improve the large/multiple file locking speed, and prevent it from hanging.
 - [ ] Perform some cleanup of the backend `lockers`.
 - [ ] Add some documentation to the app source code.
 - [ ] Add documentaton to the `lockers`.

and maybe...
 - [ ] convert it to a stanalone app?


[//]: # (Links to various places)

[1]: <https://github.com/Legrandin/pycryptodome#pycryptodome> 
"Pycryptodome - a self-contained Python package of low-level cryptographic primitives."
[2]: <https://github.com/pyca/cryptography#pycacryptography> 
"pyca/cryptography - a package which provides cryptographic recipes and primitives 
to Python developers."
[3]: <https://github.com/arunanshub/pycryptor/tree/master/File_vault/toolkit/backends>
"The spine and bone of the app... :)"
