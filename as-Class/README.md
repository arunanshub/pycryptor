# Locker (as Class)

- Here the Locker(s) are implemented as `class`. Here's how you would use them:-
		
		# Suppose we have a file called "file.txt"
		 
		>>> locker_obj = Locker('file.txt')
		>>> locker_obj.password = b'not for prying eyes'
		>>> locker_obj.locker()
		<Locker: method=`encrypt`, password=True>
		 
		# And the file gets encrypted and renamed as "file.txt.0DAY"

- But there is the provision to change the extension to suite your needs.
   Here's how you would do that:-
				
		# Let's assume there is a file called "foo.txt"
		# For now, this ordering is important.
		 
		>>> locker_obj = Locker('foo.txt')
		>>> locker_obj.EXT = '.foo_file'
		>>> locker_obj.password = b'no not this'
		>>> locker_obj.locker()
		<Locker: method=`encrypt`, password=True>
		 
	    # And the file "foo.txt" changes to "foo.txt.foo_file"

- You can also lock a file directly using Locker like this:-

		# Assume there exists "file_foo.txt"
		 
		>>> Locker('file_foo.txt', password=b'a password').locker()
		<Locker: method=`encrypt`, password=True>
		 
		# And the file is locked...

> Please note that this Locker is fully functional, although under 
> construction. So if there is a bug that catches your attention, 
> please let me know. This will help me to improve the code for
> better.
