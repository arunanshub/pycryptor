# Locker (as Class)

__This is just an experiment and I suggest not to use this. Instead use
the functional `locker` which can be found [here][1].__

- Here the Locker(s) are implemented as `class`. Here's how you would use them:-
		
	```python
	# Suppose we have a file called "file.txt"

	>>> locker_obj = Locker('file.txt')
	>>> locker_obj.password = b'not for prying eyes'
	>>> locker_obj.locker()

	# And the file gets encrypted and renamed as "file.txt.0DAY"
	```

- But there is the provision to change the file's name and path.
   Here's how you would do that:-
				
	```python
	# Let's assume there is a file called "foo.txt"
	# Please note that this ordering is important.

	>>> locker_obj = Locker('foo.txt')
	>>> locker_obj.password = b'no not this'
	>>> locker_obj.locker(new_file='file2.txt')

	# And the file "foo.txt" changes to "file2.txt"
	```

> Please note that this Locker is fully functional, although under 
> construction. So if there is a bug that catches your attention, 
> please let me know. This will help me to improve the code for
> better.

[1]: <../File_vault/toolkit/backends/README.md#the-core>
