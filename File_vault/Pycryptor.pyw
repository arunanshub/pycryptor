# GUI inspired from captainAyan/pycryptor
import re
import sys
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk
from tkinter.font import Font

from toolkit.utils import backloader, AppColors, AppUrls, messages

from toolkit.controller import Controller

if not any(backloader.backends().values()):
    _ = tk.Tk()
    _.withdraw()
    messagebox.showerror("Pycryptor", messages.no_backend_error)
    raise SystemExit(1)


class MainApplication(tk.Frame):
    """
    The Application class.
    """
    extension = ".0DAY"
    backend = backloader.get_backend()
    backend_module = backloader.change_backend(backend)
    dklen = 32

    # options for Option-Menu
    key_lens = (16, 24, 32)
    backends = [k for k, v in backloader.backends().items() if v]

    version_no = "2.3.2"

    # general help, about, and formalities... :)
    aboutmsg = messages.aboutmsg
    credits_ = messages.credits_
    help_msg = messages.help_msg
    config_help = messages.config_help

    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        style = ttk.Style()
        style.configure("BW.TLabel",
                        foreground=AppColors.color_white.value,
                        background=AppColors.color_primary_dark.value)

        top = tk.PanedWindow(self.parent,
                             bg=AppColors.color_primary_dark.value)
        custom_font = Font(size=10)

        # setup list
        list_label = tk.Label(top,
                              bg=AppColors.color_primary_dark.value,
                              fg=AppColors.color_white.value,
                              text="Selected files:")

        # create the listbox with scrollbars
        listbox = tk.Listbox(
            top,
            borderwidth=0,
            highlightbackground=AppColors.color_accent_dark.value,
            bg=AppColors.color_accent_dark.value,
            fg=AppColors.color_white.value,
        )
        # x and y scrollbars with correct orientation
        xscrollbar = ttk.Scrollbar(listbox, orient='horizontal')
        yscrollbar = ttk.Scrollbar(listbox, orient='vertical')
        # pack them on the listbox
        xscrollbar.pack(side='bottom', fill='x')
        yscrollbar.pack(side='right', fill='y')
        # configure the listbox
        listbox.configure(xscrollcommand=xscrollbar.set,
                          yscrollcommand=yscrollbar.set)
        # set the scrollbar commands
        xscrollbar.config(command=listbox.xview)
        yscrollbar.config(command=listbox.yview)
        # pass the listbox to `Controller`
        ctrl = Controller(
            list(),
            listbox,
            parent=self.parent,
        )

        # input box
        password_label = ttk.Label(top, text="Password :", style="BW.TLabel")
        password_input = tk.Entry(
            top,
            borderwidth=0,
            highlightbackground=AppColors.color_accent_dark.value,
            bg=AppColors.color_accent_dark.value,
            fg=AppColors.color_white.value,
            font=custom_font,
            show="\u2022",
        )

        # top menu
        menubar = tk.Menu(top)
        filemenu1 = tk.Menu(menubar, tearoff=0)
        filemenu1.add_command(label="Add", command=ctrl.add)
        filemenu1.add_command(
            label="Encrypt",
            command=lambda: ctrl.encrypt(password_input.get().encode(),
                                         self.extension,
                                         self.dklen,
                                         backend=self.backend_module),
        )
        filemenu1.add_command(
            label="Decrypt",
            command=lambda: ctrl.decrypt(password_input.get().encode(),
                                         self.extension,
                                         self.dklen,
                                         backend=self.backend_module),
        )
        filemenu1.add_separator()
        filemenu1.add_command(label="Configure...",
                              command=lambda: self.config_box())
        filemenu1.add_separator()
        filemenu1.add_command(label="Exit", command=lambda: root.destroy())

        menubar.add_cascade(label="Options", menu=filemenu1)
        filemenu2 = tk.Menu(menubar, tearoff=0)
        filemenu2.add_command(
            label="Help",
            command=lambda: messagebox.showinfo(
                "Pycryptor", self.help_msg.format(version=self.version_no)),
        )

        filemenu2.add_separator()
        filemenu2.add_command(
            label="About",
            command=lambda: messagebox.showinfo(
                "Pycryptor", self.aboutmsg.format(version=self.version_no)),
        )
        filemenu2.add_command(
            label="Credits",
            command=lambda: messagebox.showinfo(
                "Credits", self.credits_.format(version=self.version_no)),
        )
        filemenu2.add_separator()
        filemenu2.add_command(
            label="Visit This app on GitHub",
            command=lambda: webbrowser.open(AppUrls.app_url.value),
        )
        filemenu2.add_command(
            label="Visit Me on GitHub",
            command=lambda: webbrowser.open(AppUrls.user_url.value),
        )
        filemenu2.add_command(
            label="About AES-GCM mode",
            command=lambda: webbrowser.open(AppUrls.aes_gcm_wiki_url.value),
        )
        menubar.add_cascade(label="Help", menu=filemenu2)

        # encryption and decryption button
        encrypt_btn = tk.Button(
            top,
            text="Encrypt",
            command=lambda: ctrl.encrypt(
                password_input.get().encode(),
                self.extension,
                self.dklen,
                backend=self.backend_module,
            ),
            bg=AppColors.color_accent_dark.value,
            fg=AppColors.color_white.value,
            borderwidth=0,
            font=custom_font,
        )

        decrypt_btn = tk.Button(
            top,
            text="Decrypt",
            command=lambda: ctrl.decrypt(
                password_input.get().encode(),
                self.extension,
                self.dklen,
                backend=self.backend_module,
            ),
            bg=AppColors.color_accent_dark.value,
            fg=AppColors.color_white.value,
            borderwidth=0,
            font=custom_font,
        )

        # file add and remove button
        add_btn = tk.Button(
            top,
            text="Add",
            command=ctrl.add,
            bg=AppColors.color_primary.value,
            fg=AppColors.color_white.value,
            borderwidth=0,
        )

        remove_btn = tk.Button(
            top,
            text="Remove",
            command=ctrl.remove,
            bg=AppColors.color_danger.value,
            fg=AppColors.color_white.value,
            borderwidth=0,
        )

        removeall_btn = tk.Button(
            top,
            text="Remove All",
            command=ctrl.remove_all,
            bg=AppColors.color_danger.value,
            fg=AppColors.color_white.value,
            borderwidth=0,
        )

        # element placement
        add_btn.place(height=30, width=70, x=210, y=305)
        removeall_btn.place(height=30, width=90, x=290, y=305)  # file add btn
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
        self.parent.protocol("WM_DELETE_WINDOW", self.parent.destroy)

    def config_box(self):
        self.conf = tk.Toplevel(self.parent)
        self._dklen = tk.IntVar(self.conf, self.dklen, "_dklen")
        self._backend = tk.StringVar(self.parent, self.backends[0], "_backend")

        self.conf.resizable(0, 0)
        self.conf.geometry("300x175")
        self.conf.title("Pycryptor Configurations")

        # Elements of the config box
        fr = tk.LabelFrame(self.conf, text="Pycryptor Configuration")
        fr.place(x=10, y=10, height=120, width=280)

        # row 1 == Extension name
        tk.Label(
            fr,
            text="Encryption Extension:",
        ).place(x=5, y=5)
        self.ext = ttk.Entry(fr, width=15)
        self.ext.insert(0, self.extension)
        self.ext.place(x=150, y=5)

        # row 2 == Key length
        tk.Label(fr, text="Key Length:").place(x=70, y=35)
        opm = ttk.OptionMenu(fr, self._dklen, self.dklen, *self.key_lens)
        opm.config(width=9)
        opm.place(x=150, y=35)

        # row 3 == Default backend
        tk.Label(fr, text="Backend:").place(x=87, y=70)
        opm2 = ttk.OptionMenu(fr, self._backend, self.backend, *self.backends)
        opm2.config(width=9)
        opm2.place(x=150, y=70)

        # after the frame
        # the Buttons (Apply, Cancel, Help)
        ttk.Button(
            self.conf,
            text="Help",  # help button
            command=lambda: messagebox.showinfo("Configuration Help", self.
                                                config_help),
        ).place(x=10, y=140)

        ttk.Button(
            self.conf,
            text="Apply",
            command=self.config_apply  # apply button
        ).place(x=108, y=140)

        ttk.Button(  # cancel button
            self.conf,
            text="Cancel",
            command=self.conf.destroy).place(x=206, y=140)

        if self.parent.iconname() is not None:
            self.conf.iconbitmap(self.parent.iconname())

        self.conf.transient(self.parent)
        self.conf.focus_set()
        self.conf.grab_set()
        self.conf.wait_window()

    def config_apply(self):
        # check for extension validity
        if not re.fullmatch(r"^\.[\w|\d]+", self.ext.get()):
            messagebox.showerror("Extension Error", "Invalid Extension")
            return

        # set extension and key length
        self.dklen = self._dklen.get()
        self.extension = self.ext.get()

        # change the backend name and Title of the app :)
        self.backend = self._backend.get()
        self._set_title(f"Pycryptor - using backend {self.backend}")

        # change the backend module to the user's option.
        self.backend_module = backloader.change_backend(self.backend)
        self.conf.destroy()

    def _set_title(self, title=None):
        default = f"Pycryptor - using backend {self.backend}"
        self.parent.title(title or default)


if __name__ == "__main__":
    root = tk.Tk()
    root.resizable(0, 0)
    root.geometry("480x450")

    MainApplication(root).pack(side="top", fill="both", expand=True)

    if sys.platform == "win32":
        # this is added because tkinter on linux raised
        # an error when an app-icon was added.
        root.iconbitmap("pycryptor.ico")
        root.iconname("pycryptor.ico")
    root.mainloop()
