# GUI inspired from captainAyan/pycryptor

import tkinter as tk
import webbrowser
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter.font import Font

import sys

# add `cryptography` module support
try:
    # try checking for required module
    import Cryptodome
except ImportError:
    _ = Tk()
    _.withdraw()
    messagebox.showerror("Pycryptor",
                         "Pycryptor needs Cryptodome for encryption and "
                         "decryption, but it was not found. Please "
                         "configure your system properly.")
    sys.exit(1)

from pycryptor_tools import utility as util
from pycryptor_tools.controller import Controller


class MainApplication(tk.Frame):
    extension = '.0DAY'
    dklen = 32
    dkey = None
    ext = None
    conf = None
    key_lens = (16, 24, 32)

    version_no = "1.1.0"

	# thinking of moving `help` and `about` msgs 
	# in separate module
    aboutmsg = """Pycryptor v.{version}
Pycryptor is a portable app for encryption and
decryption of files. It is completely written in Python
and uses "AES-GCM" for encryption and decryption of files.

Features:
- Completely customisable
- Fully Open-Source
- No external dependencies needed
(except for "pycryptodomex")
- Fast file processing due to the use of threads

Also Available at: https://github.com/arunanshub/pycryptor
	"""
	
    credits = """Creators create...
Pycryptor v.{version}
	
Created with love by:
1) Arunanshu Biswas (arunanshub)
	Cryptographic File locking facilities
	Multithreading Capabilities
	... plus all backend
	(and GUI development)

Also Available at: http://github.com/arunanshub/pycryptor
    """
	
	# thinking of moving `help` and `about` msgs 
	# in separate module
    help_msg = """Pycryptor v.{version}

Color codes:
- Green  : Successful operation
- Purple : Skipped files
- Yellow : Files not found
- Red      : Failed operation

Note:
Sometimes, if big files are given for encryption
(or decryption), Pycryptor stops responding.
This is NOT a bug, as Pycryptor continues the operation.
It would be fixed later due to some unavoidable reasons,
but other than that, everything is golden.
    """
    
    config_help = """Help for Options>Configure:

    - Key length : Specify the key length.
                   32 = AES-GCM-256
                   24 = AES-GCM-192
                   16 = AES-GCM-128

    - Extension : Extension to be used for encrypted files
    """

    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        style = ttk.Style()
        style.configure("BW.TLabel",
                        foreground=util.color_white,
                        background=util.color_primary_dark)

        top = tk.PanedWindow(self.parent, bg=util.color_primary_dark)
        custom_font = Font(size=10)

        # setup list
        list_label = tk.Label(top, bg=util.color_primary_dark,
                              fg=util.color_white,
                              text="Selected files:")

        file_items = []
        tk_file_items = tk.Variable(top, value=file_items, name='file_items')
        ctrl = Controller(file_items, tk.Listbox(top, borderwidth=0,
                                                 listvariable=tk_file_items,
                                                 highlightbackground=util.
                                                 color_accent_dark,
                                                 bg=util.color_accent_dark,
                                                 fg=util.color_white))

        # input box
        password_label = ttk.Label(top, text="Password :", style="BW.TLabel")
        password_input = tk.Entry(top, borderwidth=0,
                                  highlightbackground=util.color_accent_dark,
                                  bg=util.color_accent_dark,
                                  fg=util.color_white, font=custom_font,
                                  show="\u2022")

        # top menu
        menubar = tk.Menu(top)
        filemenu1 = tk.Menu(menubar, tearoff=0)
        filemenu1.add_command(label="Add", command=ctrl.add)
        filemenu1.add_command(label="Encrypt",
                              command=lambda: ctrl.encrypt(
                                  password_input.get(),
                                  self.extension,
                                  self.dklen))
        filemenu1.add_command(label="Decrypt",
                              command=lambda: ctrl.decrypt(
                                  password_input.get(),
                                  self.extension,
                                  self.dklen))
        filemenu1.add_separator()
        filemenu1.add_command(label="Configure...",
                              command=lambda: self.config_box())
        filemenu1.add_separator()
        filemenu1.add_command(label="Exit", command=lambda: root.destroy())

        menubar.add_cascade(label="Options", menu=filemenu1)
        filemenu2 = tk.Menu(menubar, tearoff=0)
        filemenu2.add_command(label="Help",
                              command=lambda: messagebox.showinfo(
                                  "Pycryptor",
                                  self.help_msg.format(version=self.version_no)
                                  ))

        filemenu2.add_separator()
        filemenu2.add_command(label="About",
                              command=lambda: messagebox.showinfo(
                                  "Pycryptor",
                                  self.aboutmsg.format(version=self.version_no)
                                  ))
        filemenu2.add_command(label="Credits",
							  command=lambda: messagebox.showinfo(
							  	  "Credits",
							  	  self.credits.format(version=self.version_no))
							  	  )

        filemenu2.add_separator()
        filemenu2.add_command(label="Visit This app on GitHub",
                              command=lambda: webbrowser.open(
                                  "https://bit.ly/3708EGC"))
        filemenu2.add_command(label="Visit Me on GitHub",
                              command=lambda: webbrowser.open(
                                  "https://bit.ly/2NWViSH"))                          
        filemenu2.add_command(label="About AES-GCM mode",
                              command=lambda: webbrowser.open(
                                  "https://bit.ly/2zP0BOf"))
        menubar.add_cascade(label="Help", menu=filemenu2)

        # encryption and decryption button
        encrypt_btn = tk.Button(top, text="Encrypt",
                                command=lambda: ctrl.encrypt(
                                    password_input.get(),
                                    self.extension,
                                    self.dklen),
                                bg=util.color_accent_dark,
                                fg=util.color_white,
                                borderwidth=0,
                                font=custom_font)

        decrypt_btn = tk.Button(top, text="Decrypt",
                                command=lambda: ctrl.decrypt(
                                    password_input.get(),
                                    self.extension,
                                    self.dklen),
                                bg=util.color_accent_dark,
                                fg=util.color_white,
                                borderwidth=0,
                                font=custom_font)

        # file add and remove button
        add_btn = tk.Button(top, text="Add",
                            command=ctrl.add,
                            bg=util.color_primary,
                            fg=util.color_white,
                            borderwidth=0)

        remove_btn = tk.Button(top, text="Remove",
                               command=ctrl.remove,
                               bg=util.color_danger,
                               fg=util.color_white,
                               borderwidth=0)

        # element placement
        add_btn.place(height=30, width=60, x=315, y=305)  # file add btn
        remove_btn.place(height=30, width=70, x=390, y=305)  # file remove btn

        # start encryption btn
        encrypt_btn.place(height=50, width=200, x=20, y=380)
        # start decryption btn
        decrypt_btn.place(height=50, width=200, x=260, y=380)
        # file list label
        list_label.place(height=20, x=15, y=10)
        # file listbox
        ctrl.tk_listbox.place(height=250, width=350, x=110, y=40)
        # password input label
        password_label.place(height=20, width=100, x=15, y=345)
        # password input
        password_input.place(height=20, width=350, x=110, y=345)
        # parent element
        top.place(height=450, width=480, x=0, y=0)
        # show menubar
        root.config(menu=menubar)

    def config_box(self):
        self.conf = Toplevel(self.parent)
        self.dkey = IntVar(self.conf, self.dklen, 'dklen')
        self.conf.resizable(0, 0)
        self.conf.geometry('270x145')
        self.conf.title('Pycryptor Configurations')

        fr = LabelFrame(self.conf, text="Pycryptor Configuration")
        fr.place(x=10, y=10, height=90, width=250)

        # row 1
        Label(fr, text="Encryption Extension:", ).place(x=5, y=5)
        self.ext = ttk.Entry(fr, width=12)
        self.ext.insert(0, self.extension)
        self.ext.place(x=150, y=5)

        # row 2
        Label(fr, text="Key Length:", ).place(x=56, y=35)

        opm = ttk.OptionMenu(fr, self.dkey, self.dklen,
                             *self.key_lens)
        opm.config(width=8)
        opm.place(x=150, y=35)

        # after the frame
        ttk.Button(
            self.conf, text='Help',  # help button
            command=lambda: messagebox.showinfo("Configuration Help",
                                                self.config_help)
                                                ).place(x=10, y=110)

        ttk.Button(self.conf, text='Apply',  # apply button
                   command=self.config_apply).place(x=97, y=110)

        ttk.Button(self.conf, text='Cancel',  # cancel button
                   command=self.conf.destroy).place(x=185, y=110)
        
        if sys.platform == 'win32':
			# this is added because tkinter on linux raised
			# an error when an app-icon was added.
        	self.conf.wm_iconbitmap('pycryptor.ico')
        
        self.conf.transient(self.parent)
        self.conf.focus_set()
        self.conf.grab_set()
        self.conf.wait_window()

    def config_apply(self):
        if not re.fullmatch(r'^\.[\w|\d]+', self.ext.get()):
            messagebox.showerror('Extension Error', 'Invalid Extension')
            return
        self.dklen = self.dkey.get()
        self.extension = self.ext.get()
        self.conf.destroy()


if __name__ == '__main__':
	root = tk.Tk()
	root.title("Pycryptor")
	root.resizable(0, 0)
	root.geometry("480x450")

	MainApplication(root).pack(side="top", fill="both", expand=True)
	
	if sys.platform == 'win32':
		# this is added because tkinter on linux raised
		# an error when an app-icon was added.
		root.wm_iconbitmap('pycryptor.ico')

	root.mainloop()
