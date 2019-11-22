# GUI inspired from captainAyan/pycryptor
import sys
import pkgutil
import tkinter as tk
import webbrowser
from tkinter import *
from tkinter import messagebox, ttk
from tkinter.font import Font

from toolkit import utility as util
from toolkit.controller import Controller


if not any(util.backends().values()):
    _ = Tk()
    _.withdraw()
    messagebox.showerror("Pycryptor", util.no_backend_error)
    sys.exit(1)

class MainApplication(tk.Frame):
    extension = '.0DAY'
    backend = util.get_backend()
    backend_module = util.change_backend(backend)
    dklen = 32

    # options for Option-Menu
    key_lens = (16, 24, 32)
    backends = [k for k, v in util.backends().items() if v]

    # Tk variables for Entry/Option-menus
    # _dklen = None
    # _backend
    # ext = None
    # conf = None

    version_no = "2.0.0"

    # general help, about, and formalities... :)
    aboutmsg = util.aboutmsg
    credits_ = util.credits_
    help_msg = util.help_msg
    config_help = util.config_help

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
	  command=lambda: messagebox.showinfo("Credits",
					      self.credits_.format(version=self.version_no)))

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
                                    self.dklen,
                                    backend=self.backend_module),
                                bg=util.color_accent_dark,
                                fg=util.color_white,
                                borderwidth=0,
                                font=custom_font)

        decrypt_btn = tk.Button(top, text="Decrypt",
                                command=lambda: ctrl.decrypt(
                                    password_input.get(),
                                    self.extension,
                                    self.dklen,
                                    backend=self.backend_module),
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

        self._set_title()
        self.parent.protocol('WM_DELETE_WINDOW', self.parent.destroy)

    def config_box(self):
        self.conf = Toplevel(self.parent)
        self._dklen = IntVar(self.conf, self.dklen, '_dklen')
        self._backend = StringVar(self.parent, self.backends[0], '_backend')
        
        self.conf.resizable(0, 0)
        self.conf.geometry('300x175')
        self.conf.title('Pycryptor Configurations')

        # Elements of the config box
        fr = LabelFrame(self.conf, text="Pycryptor Configuration")
        fr.place(x=10, y=10, height=120, width=280)

        # row 1 == Extension name
        Label(fr, text="Encryption Extension:", ).place(x=5, y=5)
        self.ext = ttk.Entry(fr, width=15)
        self.ext.insert(0, self.extension)
        self.ext.place(x=150, y=5)

        # row 2 == Key length
        Label(fr, text="Key Length:").place(x=70, y=35)
        opm = ttk.OptionMenu(fr, self._dklen, self.dklen,
                             *self.key_lens)
        opm.config(width=9)
        opm.place(x=150, y=35)

        # row 3 == Default backend
        Label(fr, text="Backend:").place(x=87, y=70)
        opm2 = ttk.OptionMenu(fr, self._backend, self.backend,
                              *self.backends)
        opm2.config(width=9)
        opm2.place(x=150, y=70)

        # after the frame
        # the Buttons (Apply, Cancel, Help)
        ttk.Button(
            self.conf, text='Help',  # help button
            command=lambda: messagebox.showinfo("Configuration Help",
                                                self.config_help)
                                                ).place(x=10, y=140)

        ttk.Button(self.conf, text='Apply',  # apply button
                   command=self.config_apply).place(x=108, y=140)

        ttk.Button(self.conf, text='Cancel',  # cancel button
                   command=self.conf.destroy).place(x=206, y=140)

        if sys.platform == 'win32':
			# this is added because tkinter on linux raised
			# an error when an app-icon was added.
        	self.conf.iconbitmap('pycryptor.ico')

        self.conf.transient(self.parent)
        self.conf.focus_set()
        self.conf.grab_set()
        self.conf.wait_window()

    def config_apply(self):
        
        # check for extension validity
        if not re.fullmatch(r'^\.[\w|\d]+', self.ext.get()):
            messagebox.showerror('Extension Error',
                                 'Invalid Extension')
            return

        # set extension and key length
        self.dklen = self._dklen.get()
        self.extension = self.ext.get()

        # change the backend name and Title of the app :)
        self.backend = self._backend.get()
        self._set_title(f"Pycryptor - using backend {self.backend}")
        
        # change the backend module to the user's option.
        self.backend_module = util.change_backend(self.backend)
        self.conf.destroy()


    def _set_title(self, title=None):
        default = f"Pycryptor - using backend {self.backend}"
        self.parent.title(title or default)


if __name__ == '__main__':
    root = tk.Tk()
    root.resizable(0, 0)
    root.geometry("480x450")

    MainApplication(root).pack(side="top", fill="both", expand=True)

    if sys.platform == 'win32':
        # this is added because tkinter on linux raised
        # an error when an app-icon was added.
        root.iconbitmap('pycryptor.ico')

    root.mainloop()
