import tkinter as tk
import webbrowser
from tkinter import ttk, filedialog, messagebox

AES_WIKI = "https://en.wikipedia.org/wiki/Advanced_Encryption_Standard"
ABOUT_APP = (
    "https://github.com/arunanshub/pycryptor#pycryptor---the-file-vault"
)
ABOUT_ME = "https://github.com/arunanshub"


class ListBox(tk.Listbox):
    """The List box.

    add -- Add items
    remove -- remove items
    clear -- clear items
    get -- get all items
    """

    def __init__(self, *args, master, **kwargs):
        super().__init__(*args, master=master, **kwargs)
        self.__items = tk.Variable(master, name="__items")
        self.config(listvariable=self.__items)

        # x and y scrollbars with correct orientation
        xscrollbar = ttk.Scrollbar(self, orient="horizontal")
        yscrollbar = ttk.Scrollbar(self, orient="vertical")

        # pack them on the listbox
        xscrollbar.pack(side="bottom", fill="x")
        yscrollbar.pack(side="right", fill="y")

        # configure the listbox
        self.configure(
            xscrollcommand=xscrollbar.set,
            yscrollcommand=yscrollbar.set,
        )

        # set the scrollbar commands
        xscrollbar.config(command=self.xview)
        yscrollbar.config(command=self.yview)

        # TODO: Fix the flashing of window caused by the addition
        # of scrollbars.
        # The flashing could be cause due to the fact that we are
        # using pack here and grid in other places, ie., geometry
        # manager conficts?
        # Currently, the flashing stops if the window is resized
        # slightly.

    @property
    def items(self):
        return self.getvar("__items") or ()

    def get(self):
        """Get the items from the ListBox"""
        return self._items.get()

    def add(self, item):
        """Add a unique item in the ListBox"""
        if item not in self.items:
            self.insert("end", item)

    def add_many(self, *items):
        """Add several items at once."""
        for item in items:
            self.add(item)

    def clear(self):
        """Clear the ListBox"""
        self.delete(0, "end")

    remove_all = clear

    def remove(self):
        """Remove a single selected item from the ListBox"""
        try:
            idx = self.curselection()[0]
            self.delete(idx)
        except IndexError:
            messagebox.showerror("Error", "No file selected.")


class ARCFrame(ttk.Frame):
    """Add, Remove, Clear Frame;
        * controls ListBoxFrame

    listbox -- the listbox to control
    on_add -- Add ctrl.
    on_remove -- rm ctrl.
    on_clear -- clearing ctrl. Aliased to 'Remove All'
    """

    def __init__(self, *args, master, listbox=None, **kwargs):
        super().__init__(*args, master=master, **kwargs)
        self._listbox = listbox  # assume packed: EIBTI

        self._badd = ttk.Button(
            self,
            text="Add",
            command=self.on_add,
        )
        self._bremove = ttk.Button(
            self,
            text="Remove",
            command=self.on_remove,
        )
        self._bclear = ttk.Button(
            self,
            text="Clear",
            command=self.on_clear,
        )

        self._badd.grid(row=0, column=0, sticky="nsew")
        self._bremove.grid(row=0, column=1, sticky="nsew", padx=10)
        self._bclear.grid(row=0, column=2, sticky="nsew")

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)

    def on_add(self):
        """Open a DialogBox to select item(s) and add it to the listbox."""
        filepath = filedialog.askopenfilenames()
        if not filepath:
            return
        self._listbox.add_many(*filepath)

    def on_remove(self):
        """Remove a selected item from the listbox (Button mapped)"""
        self._listbox.remove()

    def on_clear(self):
        """Clear (or remove_all) the listbox (button mapped)"""
        self._listbox.clear()

    on_remove_all = on_clear


class EncDecFrame(ttk.Frame):
    """Encrypt / Decrypt buttons w/ a password entry.
        * Controls ListBox

    on_encrypt -- enc
    on_decrypt -- dec
    """

    def __init__(self, *args, master, listbox, **kwargs):
        super().__init__(*args, master=master, **kwargs)
        self._listbox = listbox  # assume packed: EIBTI

        self._bencrypt = ttk.Button(
            self,
            text="Encrypt",
            command=self.on_encrypt,
        )
        self._bdecrypt = ttk.Button(
            self,
            text="Decrypt",
            command=self.on_decrypt,
        )

        # Row 0: [Frame: [Label: Password-entry]]
        pwd_frame = ttk.Frame(self)
        self._entry_pwd = ttk.Entry(pwd_frame, show="\u2022")

        ttk.Label(pwd_frame, text="Password:").grid(
            row=0,
            column=0,
            sticky="w",
            padx=(0, 20),
        )
        self._entry_pwd.grid(
            row=0,
            column=1,
            sticky="ew",
        )
        pwd_frame.grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(0, 20),
        )
        pwd_frame.columnconfigure(1, weight=1)  # let the ttk.Entry expand

        # Row 1: [Encrypt, Decrypt]
        self._bencrypt.grid(
            row=1,
            column=0,
            sticky="nsew",
        )
        self._bdecrypt.grid(
            row=1,
            column=1,
            sticky="nsew",
        )

        self.rowconfigure(1, weight=1)  # expand the buttons row-wise
        self.columnconfigure(0, weight=1)  # expand buttons columnwise
        self.columnconfigure(1, weight=1)  # expand buttons columnwise

    def on_encrypt(self):
        """Encrypt everything in the listbox."""
        print("encrypting")
        print(repr(self._listbox.items), self._entry_pwd.get())

    def on_decrypt(self):
        """Decrypt everything in the listbox."""
        print("decrypting")
        print(repr(self._listbox.items), self._entry_pwd.get())


class ControlFrame(ttk.Frame):
    """Full control of listbox. Set up as required.

    - Resize the listbox to correct size.
    - Place ARC buttons below the listbox in this way:

        [Add, Remove, Remove All]

    - Place the password entry (controlled by EncDecFrame)
    - Place the Enc and Dec buttons in this way:

        [Encrypt, Decrypt]
    """

    def __init__(self, *args, master, **kwargs):
        super().__init__(*args, master=master, **kwargs)
        self._listbox = ListBox(*args, master=self, **kwargs)

        # pack with an internal padding otherwise the listbox will
        # look like shit.
        self._listbox.grid(
            row=0,
            column=0,
            ipadx=250,
            ipady=250,
            sticky="nsew",  # expand in all directions
        )

        arcf = ARCFrame(master=self, listbox=self._listbox)
        arcf.grid(
            row=1,
            column=0,
            sticky="nsew",  # expand in all directions
            ipady=5,
            pady=20,
        )
        encf = EncDecFrame(master=self, listbox=self._listbox)
        encf.grid(
            row=2,
            column=0,
            ipady=5,
            sticky="nsew",  # expand in all directions
        )

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=4)  # the listbox must expand faster.
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        # Configure a menu
        menu = tk.Menu(master)

        filem = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label="File", menu=filem)
        filem.add_command(label="Add", command=arcf.on_add)
        filem.add_command(label="Remove All", command=arcf.on_remove_all)
        filem.add_separator()
        filem.add_command(label="Configure...", command=lambda: None)

        aboutm = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label="About", menu=aboutm)
        aboutm.add_command(
            label="About the App...",
            command=lambda: webbrowser.open(ABOUT_APP),
        )
        aboutm.add_command(
            label="About Me...", command=lambda: webbrowser.open(ABOUT_ME)
        )
        aboutm.add_command(
            label="About AES...", command=lambda: webbrowser.open(AES_WIKI)
        )

        master.config(menu=menu)


if __name__ == "__main__":
    root = tk.Tk()
    cf = ControlFrame(master=root)
    cf.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
    root.mainloop()
