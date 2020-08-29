# Pycryptor - The File Vault

A pure Python file vault, backed by the powerful cryptographic libraries,
namely [`Pycryptodome(x)`][6] and [`cryptography`][7]. Inspired by the
other cryptographic file locking apps on the internet today, this app was
born to serve the same purpose, although faster.


## Features

This app supports both the libraries, and has a very fast operating file
locker module, which is kept in [`toolkit/backends`][3].

The app has been designed in such a way that it is easy for the user to
modify and incorporate it in their own projects. Feel free to test it
and provide feedback to me. This would help me to improve this app in
the long run.


## The `locker` modules

**WARNING: The locker modules will be deprecated in favour of a better file
locking API. This also means, the file header format that are used to store
the metadata will be changed for a newer format.**

This is the core of Pycryptor. These two modules [`pylocker.py`][4] and
[`crylocker.py`][5] can be used as standalone file lockers. Actually,
that was my idea for this repo. But eventually, the app was made (and the
rest is Pycryptor).

**`pylocker.py`** uses the backend [Pycryptodome(x)][6] and
**`crylocker.py`** uses the backend [cryptography][7].

**The class based `locker` has been removed.**


### Using the lockers

Both the lockers are quite straightforward to use

 - Basics

	Locking files.
	```python
	# Let's use crylocker and suppose that we have files named
	# as 'lockme.txt', 'extchange.txt'.
	# Let's see the basics of the module.

	>>> import os
	>>> from crylocker import locker
	>>> print(os.listdir('.'))
	['lockme.txt', 'extchange.txt']
	>>> locker('file.txt', b'helloworld')
	>>> print(os.listdir('.'))
	['lockme.txt.0DAY', 'extchange.txt']
	```

	Changing the extension and keeping the original file.

	```python
	# the file is renamed with the default extension
	# (here '.0DAY') but here's how you would change the
	# extension of the file.

	>>> locker('extchange.txt', b'no not this',
		   ext='.aes'
		   remove=False)
	>>> print(os.listdir('.')
	['file.txt.0DAY', 'extchange.txt.aes', 'extchange.txt']
	```
	Changing the file location
	```python
	# Changing the file location is very easy.

	>>> new_path = r'/a/new/file/path/foofile.txt'
	>>> locker('foofile.txt', b'helloworld',
		   new_file=new_path)

	# the file would be saved in the provided path.
	# Please note that argument `ext` will have no effect
	# if this is used.
	```

 - Some advanced things...

	Changing the primitives

	```python
	# You can change
	# 1. the number of iterations for the key derivation
	# 2. the hash algorithm to use
	# 3. the key length after derivation
	#    (this changes the AES-GCM's mode i.e. 256, 192 or 128)
	# 4. metadata appended to the file

	>>> file_path = r'/your/path/to/file.txt'
	>>> meta = b'my-custom-metadata'
	>>> locker(file_path, b'hellocrypto',
		   dklen=24,	      # default is 24
		   algo='sha512',     # default is 'sha512'
		   iterations=20000,  # default is 50000
		   metadata=meta
		   )

	# then the file would be locked with the given params.
	```

	Changing the method (or mode) used by the locker

	```python
	# Suppose you have a file 'foolocked.txt' and you want
	# to decrypt it.

	>>> locker('foolocked.txt', b'helloworld',
		   method='decrypt',
		   remove=False)

	# a file with name 'foolocked' would be created.
	# This is best used with `new_file` keyword.

	>>> locker('foolocked.txt', b'helloworld',
		   method='decrypt',
		   new_file='foo_unlocked.txt'
		   )

	# A file with name 'foo_unlocked.txt' would be created.
	```


## Future plans for the App

A small checklist in case I forget my tasks!

 - [x] Add multiple backend support for the app
 - [x] Make [`crylocker.py`][5] compatible with [`pylocker.py`][4]
 - [x] Shift the hyperlinks in the app to some better place.
 - [x] Improve the large/multiple file locking speed, and prevent it from hanging.
 - [x] Perform some cleanup of the backend `lockers`.
 - [x] Add some documentation to the app source code.
 - [x] Add documentaton to the `lockers`.
 - [ ] Add functionality to work with directories.
 - [x] Deprecate the locker in favour of better API.
    - [ ] Remove the locker files.

and maybe...
 - [ ] convert it to a stanalone app?


## Where is the ransomware?

The ransomware has been removed due to difficulty in maintenance
(and also due to the fact that better implementations are available)
But it would probably be released in a separate repo.


[3]: <pycryptor/toolkit/backends>
[4]: <pycryptor/toolkit/backends/pylocker.py>
[5]: <pycryptor/toolkit/backends/crylocker.py>
[6]: <https://github.com/Legrandin/pycryptodome#pycryptodome>
[7]: <https://github.com/pyca/cryptography#pycacryptography>

