import tkinter as tk
import webbrowser
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter.font import Font

from pycryptor_tools import utility as util
from pycryptor_tools.controller import Controller


class MainApplication(tk.Frame):
    extension = '.0DAY'
    dklen = 32
    dkey = None
    ext = None
    conf = None
    key_lens = (16, 24, 32)

    version_no = "1.0.0"

    aboutmsg = r"""Pycryptor
A special application for encryption and
decryption of files.

v1.0
Created with love by:
    1) Arunanshu Biswas (arunanshub)
           Cryptographic File locking facilities.
           Multiprocessing Capabilities

Available at:
    http://github.com/arunanshub/pycryptor
    """

    help_msg = """Pycryptor v.{version}
Pycryptor is a portable app for encryption and
decryption of files. It is completely written in Python 
and uses "AES-GCM" for encryption and decryption of files.
    
Features:
    - Completely customisable
    - Fully Open-Source
    - No external dependencies needed (except for files in `requirements.txt`)
    - Fast file processing due to the use of threads.
    
Color codes:
    - Green : Successful operation
    - Purple : Skipped files
    - Yellow : Files not found
    - Red : Failed operation
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

        top = tk.PanedWindow(root, bg=util.color_primary_dark)
        custom_font = Font(size=10)

        # setup list
        list_label = tk.Label(top, bg=util.color_primary_dark,
                              fg=util.color_white,
                              text="Selected files :")

        file_items = []
        tk_file_items = tk.Variable(top, value=file_items, name='file_items')
        ctrl = Controller(file_items, tk.Listbox(top, borderwidth=0,
                                                 listvariable=tk_file_items,
                                                 highlightbackground=util.color_accent_dark,
                                                 bg=util.color_accent_dark,
                                                 fg=util.color_white, ), )

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
                              command=lambda: ctrl.encrypt(password_input.get(),
                                                           self.extension,
                                                           self.dklen))
        filemenu1.add_command(label="Decrypt",
                              command=lambda: ctrl.decrypt(password_input.get(),
                                                           self.extension,
                                                           self.dklen))
        filemenu1.add_separator()
        filemenu1.add_command(label="Configure...", command=lambda: self.config_box())
        filemenu1.add_separator()
        filemenu1.add_command(label="Exit", command=lambda: root.destroy())

        menubar.add_cascade(label="Options", menu=filemenu1)
        filemenu2 = tk.Menu(menubar, tearoff=0)
        filemenu2.add_command(label="Help",
                              command=lambda: messagebox.showinfo("Pycryptor",
                                                                  self.help_msg.format(version=self.version_no)))
        filemenu2.add_separator()
        filemenu2.add_command(label="About",
                              command=lambda: messagebox.showinfo("Pycryptor", self.aboutmsg))
        filemenu2.add_command(label="Visit Me on the Web",
                              command=lambda: webbrowser.open("https://github.com/arunanshub/pycryptor"))
        menubar.add_cascade(label="Help", menu=filemenu2)

        # encryption and decryption button
        encrypt_btn = tk.Button(top, text="Encrypt",
                                command=lambda: ctrl.encrypt(password_input.get(),
                                                             self.extension,
                                                             self.dklen, ),
                                bg=util.color_accent_dark,
                                fg=util.color_white,
                                borderwidth=0,
                                font=custom_font)

        decrypt_btn = tk.Button(top, text="Decrypt",
                                command=lambda: ctrl.decrypt(password_input.get(),
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
        add_btn.place(height=30, width=60, x=350, y=260)  # file add btn
        remove_btn.place(height=30, width=70, x=420, y=260)  # file remove btn
        encrypt_btn.place(height=40, width=100, x=10, y=35)  # start encryption btn
        decrypt_btn.place(height=40, width=100, x=10, y=85)  # start decryption btn
        list_label.place(height=20, x=120, y=10)  # file list label
        ctrl.tk_listbox.place(height=175, width=370, x=120, y=35)  # file list
        password_label.place(height=20, width=60, x=120, y=230)  # password input label
        password_input.place(height=20, width=300, x=190, y=230)  # password input
        top.place(height=300, width=600, x=0, y=0)  # parent element
        root.config(menu=menubar)  # setup menu

    def config_box(self):
        self.conf = Toplevel(root)  # bg=util.color_accent_dark)
        self.dkey = IntVar(self.conf, self.dklen, 'dklen')
        self.conf.resizable(0, 0)
        self.conf.title('Pycryptor Configurations')

        fr = LabelFrame(self.conf, text="Pycryptor Configuration", )
        fr.grid(row=0, columnspan=3, pady=2, padx=2, sticky='w', ipadx=25)

        # row 1
        Label(fr, text="Encryption Extension:", ).grid_configure(pady=4, sticky='w',
                                                                 row=1, column=0)
        self.ext = ttk.Entry(fr, width=10)
        self.ext.insert(0, self.extension)
        self.ext.grid(row=1, column=1, pady=4, sticky='ne')

        # row 2
        Label(fr, text="Key Length:", ).grid_configure(sticky='w', pady=2,
                                                       padx=2, row=2, column=0)
        opm = ttk.OptionMenu(fr, self.dkey, self.dklen,
                             *self.key_lens, )
        opm.config(width=6)
        opm.grid_configure(sticky='se', row=2, column=1, pady=2, padx=2)

        ttk.Button(
            self.conf, text='Help',  # apply button
            command=lambda: messagebox.showinfo("Configuration Help", self.config_help),
        ).grid(row=1, column=0,
               padx=4, pady=4, )
        ttk.Button(self.conf, text='Apply',  # apply button
                   command=self.config_apply, ).grid(row=1, column=1,
                                                     padx=4, pady=4, )
        ttk.Button(self.conf, text='Cancel',  # cancel button
                   command=self.conf.destroy, ).grid(row=1, column=2,
                                                     padx=4, pady=4, )

        self.conf.wm_iconbitmap('pycryptor.ico')
        self.conf.transient(root)
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
    root.geometry("500x300")
    MainApplication(root).pack(side="top", fill="both", expand=True)
    root.wm_iconbitmap('pycryptor.ico')
    root.mainloop()
