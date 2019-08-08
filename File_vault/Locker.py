#!/usr/bin/python
# -*- coding: utf-8 -*-
# Locker v4.0 (follows new protocol)
# Implemented as function
#
# =============================================================================
# MIT License

# Copyright (c) 2019 Arunanshu Biswas

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =============================================================================

import hashlib
import os
import stat
import string
from struct import pack, unpack

from functools import lru_cache
from Cryptodome.Cipher import AES


class DecryptionError(ValueError):
    pass


def _writer(file_path, new_file, method, flag, **kwargs):
    """Facilitates reading/writing to file.
    This function facilitates reading from *file_path* and writing to
    *new_file* with the provided method by looping through each line
    of the file_path of fixed length, specified by *block_size*.

      Usage
     -------

    file_path = File to be written on.

     new_file = Name of the encrypted/decrypted file to written upon.

      method = The way in which the file must be overwritten.
               (encrypt or decrypt)

        flag = This is to identify if the method being used is
               for encryption or decryption.
               If the *flag* is *True* then the *nonce* value
               is written to the end of the *new_file*.
               If the *flag* is *False*, then the *nonce* is written to
               *file_path*.
    """

    salt = kwargs['salt']
    nonce = kwargs['nonce']
    mac_func = kwargs['mac_func']
    block_size = kwargs['block_size']

    os.chmod(file_path, stat.S_IRWXU)
    with open(file_path, 'rb') as fin:
        with open(new_file, 'wb+') as fout:
            if flag:
                # Create a placeholder for writing the *mac*.
                # and append *nonce* and *salt* before encryption.
                plh_nonce_salt = pack('16s12s32s',
                                      b'0' * 16, nonce, salt)
                fout.write(plh_nonce_salt)

            else:
                # Moving ahead towards the encrypted data.
                fin.seek(16 + 12 + 32)

            # Loop through the *fin*, generate encrypted data
            # and write it to *fout*.
            while True:
                part = fin.read(block_size)
                if not part:
                    break
                fout.write(method(part))

            if flag:
                fout.seek(0)
                fout.write(mac_func())


def locker(file_path, password, remove=True, **kwargs):
    """Provides file locking/unlocking mechanism
    This function either encrypts or decrypts the file - *file_path*.
    Encryption or decryption depends upon the file's extension.
    The user's encryption or decryption task is almost automated since
    *encryption* or *decryption* is determined by the file's extension.

      Usage
     -------

     file_path = File to be written on.

     password = Password to be used for encryption/decryption.

       remove = If set to True, the the file that is being
                encrypted or decrypted will be removed.
                (Default: True).
    """

    if kwargs:
        block_size = kwargs.get('block_size', 64 * 1024)
        ext = kwargs.get('ext', '.0DAY').strip(string.whitespace)
        iterations = kwargs.get('iterations', 50000)
        dklen = kwargs.get('dklen', 32)
    else:
        block_size = 64 * 1024
        ext = '.0DAY'
        iterations = 50000
        dklen = 32

    # The file is being decrypted.
    if file_path.endswith(ext):
        method = 'decrypt'
        flag = False
        new_file = os.path.splitext(file_path)[0]

        # Retrieve the *nonce* and *salt*.
        with open(file_path, 'rb') as f:
            mac, nonce, salt = unpack('16s12s32s',
                                      f.read(16 + 12 + 32))


    except Exception as err:
        raise err

        
        
        
        
        
#####################################################################################################################################       
import tkinter as tk
import tkinter.font as tkfont

from controller import Controller
import utility as util


class MainApplication(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        top = tk.PanedWindow(root, bg=util.color_primary_dark)
        custom_font = tkfont.Font(size=10)

        # setup list
        list_label = tk.Label(top, bg=util.color_primary_dark, fg=util.color_white, text="Selected files :")
        ctrl = Controller([], tk.Listbox(top, borderwidth=0, highlightbackground=util.color_accent_dark,
                                         bg=util.color_accent_dark, fg=util.color_white))
        tk.Listbox(top, borderwidth=0, highlightbackground=util.color_accent_dark, bg=util.color_accent_dark,
                   fg=util.color_white)

        # input box
        password_label = tk.Label(top, bg=util.color_primary_dark, fg=util.color_white, text="Enter Password :")
        password_input = tk.Entry(top, borderwidth=0, highlightbackground=util.color_accent_dark,
                                  bg=util.color_accent_dark, fg=util.color_white, font=custom_font, show="*")

        # top menu
        menubar = tk.Menu(top)
        filemenu1 = tk.Menu(menubar, tearoff=0)
        filemenu1.add_command(label="Add", command=ctrl.add)
        filemenu1.add_command(label="Encrypt", command=lambda: ctrl.encrypt(password_input.get()))
        filemenu1.add_command(label="Decrypt", command=ctrl.decrypt)
        filemenu1.add_separator()
        filemenu1.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="Options", menu=filemenu1)
        filemenu2 = tk.Menu(menubar, tearoff=0)
        filemenu2.add_command(label="Help")
        filemenu2.add_separator()
        filemenu2.add_command(label="About")
        menubar.add_cascade(label="Help", menu=filemenu2)

        # encryption and decryption button
        encrypt_btn = tk.Button(top, text="Encrypt", command=lambda: ctrl.encrypt(password_input.get()),
                                bg=util.color_accent_dark, fg=util.color_white, borderwidth=0, font=custom_font)
        decrypt_btn = tk.Button(top, text="Decrypt", command=lambda: ctrl.decrypt(),
                                bg=util.color_accent_dark, fg=util.color_white, borderwidth=0, font=custom_font)

        # file add and remove button
        add_btn = tk.Button(top, text="Add", command=ctrl.add, bg=util.color_primary,
                            fg=util.color_white, borderwidth=1.5)
        remove_btn = tk.Button(top, text="Remove", command=ctrl.remove, bg=util.color_danger,
                               fg=util.color_white, borderwidth=1.5)

        # element placement
        add_btn.place(height=30, width=60, x=325, y=345)  # file add btn
        remove_btn.place(height=30, width=70, x=390, y=345)  # file remove btn
        encrypt_btn.place(height=50, width=450, x=20, y=390)  # start encryption btn
        decrypt_btn.place(height=50, width=450, x=20, y=445)  # start decryption btn
        list_label.place(height=20, x=15, y=10)  # file list label
        ctrl.listbox.place(height=250, width=350, x=110, y=40)  # file list
        password_label.place(height=20, width=100, x=15, y=315)  # password input label
        password_input.place(height=20, width=350, x=110, y=315)  # password input
        top.place(height=500, width=500, x=0, y=0)  # parent element
        root.config(menu=menubar)  # setup menu


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Pycyptor")
    root.resizable(0, 0)
    root.geometry("500x500")
    MainApplication(root).pack(side="top", fill="both", expand=True)
    root.mainloop()
    ####################################################################################################################
=======
    # The file is being encrypted.
    else:
        method = 'encrypt'
        flag = True
        new_file = file_path + ext
        nonce = os.urandom(12)
        salt = os.urandom(32)
        mac = None

    # Create a *password_hash* and *cipher* with
    # required method.
    password_hash = hashlib.pbkdf2_hmac('sha512', password,
                                        salt, iterations, dklen)
    cipher_obj = AES.new(password_hash, AES.MODE_GCM,
                         nonce=nonce)
    crp = getattr(cipher_obj, method)

    _writer(file_path, new_file,
            crp, flag,
            nonce=nonce,
            mac_func=cipher_obj.digest,
            mac_val=mac,
            salt=salt, block_size=block_size, )

    if not flag:
        try:
            cipher_obj.verify(mac)
        except ValueError:
            os.remove(new_file)
            raise DecryptionError('Invalid Password or tampered data.')

    if remove:
        os.remove(file_path)
...