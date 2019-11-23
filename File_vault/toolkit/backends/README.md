# The core

This is the core of Pycryptor. These two modules can be used as standalone file lockers.

Actually, that was my idea for this repo. But eventually, the app was made (and the rest is Pycryptor).

# Using the modules

Both the modules are quite straightforward to use

 - Basics

	Locking files.
	```python
	# Let's use crylocker and suppose that we have files named
	# as 'lockme.txt', 'extchange.txt'.
	# Let's see the basics of the module.
	
	>>> import os
	>>> from crylocker import locker
	>>> print(os.listdir('.'))
	['file.txt', 'extchange.txt']
	>>> locker('file.txt', b'helloworld')
	>>> print(os.listdir('.'))
	['file.txt.0DAY', 'extchange.txt']
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
	
	Changing the method used by the locker
	```python
	# Suppose you have a file 'foolocked.txt' and you want
	# to decrypt it, without 
	
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

