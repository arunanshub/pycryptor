#!/usr/bin/python3
import re
import json
import argparse
import tkinter as tk
import webbrowser
import logging

from collections import deque, defaultdict
from tkinter import ttk, filedialog, messagebox
from threading import Thread, current_thread
from pyflocker import Backends
from pyflocker.ciphers import modes

from . import parallel, start_logging

logger = logging.getLogger(__loader__.name)

KEY_LENGTHS = (16, 24, 32)

WAIT_TIME = 200

AES_MODES = tuple(m.name for m in set(modes.Modes) ^ modes.special)

AES_WIKI = "https://en.wikipedia.org/wiki/Advanced_Encryption_Standard"

ABOUT_APP = (
    "https://github.com/arunanshub/pycryptor#pycryptor---the-file-vault"
)

ABOUT_ME = "https://github.com/arunanshub"

SETTINGS_HELP = """\
Extension: The extension to use for encrypting files.
Default is ".pyflk"

Key Length: The length of the key derived for AES cipher.
The greater the length, the stronger the encryption.
Default is 32 (the highest).

AES mode: The mode to use for underlying AES cipher.
The modes which do not support AEAD use HMAC.
Default is "MODE_GCM".

Backend: The backend provider to use for encryption and decryption.
Default is "Cryptography".
"""

WAITBOX_MESSAGE = """\
Please wait while the files are being {operation}ed.
Closing the application while the files are being {operation}ed
might lead to incorrect {operation}ion or data loss.
"""

RESULT_TEMPLATE = """\
{operation}ion results:

    Files {operation}ed: {success},
    Files failed: {failure},
    Files not found: {file_not_found},
    Invalid files: {invalid}.
"""

APP_DESC = """\
Pycryptor is a high performance file encryption GUI written in Python.
It uses AES for file encryption and decryption and supports multiple
AES modes, along with other parameters, which can be configured from
within the app.

Visit https://github.com/arunanshub/pycryptor to know more.
"""

CLI_APP_EPILOG = """\
Pycryptor is licensed under MIT license.
"""

_SENTINEL = object()


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

        logger.warning(
            "Using packer to set scrollbars. This will be replaced with grid "
            "in the near future. Side effects of packer may include flashing "
            "windows. "
        )
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
        * controls ListBox

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


class SettingsPanel(tk.Toplevel):
    """Settings panel for user-side configuration."""

    def __init__(
        self,
        *args,
        var,
        extension,
        aesmode,
        keylen,
        backend,
        master,
        **kwargs,
    ):
        super().__init__(*args, master=master, **kwargs)
        logger.debug(f"Building SettingsPanel with {var=}")

        self.title("Settings")
        self.__var = var
        # 0. Use grid.
        # 1. Extension: ttk.Entry
        # 2. Key Length: ttk.OptionMenu
        # 3. AES Mode: ttk.OptionMeneu
        # 4. Backend: ttk.OptonMenu
        # n. Theme: ...
        # 5. Help, Apply, Cancel: ttk.Frame[ttk.Button]
        # The settings must be returned to the application.
        frame = ttk.LabelFrame(self, text="Settings ")
        frame.grid(row=0, column=0, sticky="new")

        # 1. Extension: ttk.Entry
        ttk.Label(frame, text="Extension: ").grid(
            row=0,
            column=0,
            sticky="ew",
            padx=10,
            pady=(0, 5),
        )
        self.entry_ext = ttk.Entry(frame)
        self.entry_ext.insert(0, extension)
        self.entry_ext.grid(row=0, column=1, sticky="ew", padx=5, pady=(0, 5))

        # 2. Key length: ttk.OptionMenu
        ttk.Label(frame, text="Key Length: ").grid(
            row=1,
            column=0,
            sticky="ew",
            padx=10,
            pady=5,
        )

        var_keylen = tk.IntVar(frame, name="keylen")
        self.opt_klen = ttk.OptionMenu(
            frame,
            var_keylen,
            keylen,
            *KEY_LENGTHS,
        )
        self.opt_klen.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # 3. AES Mode: ttk.OptionMenu
        ttk.Label(frame, text="AES Mode: ").grid(
            row=2,
            column=0,
            sticky="ew",
            padx=10,
            pady=5,
        )

        var_aesmode = tk.StringVar(frame, name="aesmode")
        self.opt_aesmode = ttk.OptionMenu(
            frame,
            var_aesmode,
            aesmode,
            *AES_MODES,
        )
        self.opt_aesmode.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        # 4. Backend: ttk.OptionMenu
        ttk.Label(frame, text="Backend: ").grid(
            row=3,
            column=0,
            sticky="ew",
            padx=10,
            pady=5,
        )

        var_backend = tk.StringVar(frame, name="backend")
        self.opt_backend = ttk.OptionMenu(
            frame,
            var_backend,
            backend,
            *(b.name.title() for b in list(Backends)),
        )
        self.opt_backend.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # 5. Help, Apply, Cancel
        hacframe = ttk.Frame(self)
        hacframe.grid(row=1, column=0, sticky="sew", pady=5)

        bhelp = ttk.Button(
            hacframe,
            text="Help",
            command=lambda: messagebox.showinfo(
                "Help on Settings",
                "Configuring Pycryptor",
                detail=SETTINGS_HELP,
                parent=self,
            ),
        )
        bapply = ttk.Button(hacframe, text="Apply", command=self.on_apply)
        bcancel = ttk.Button(hacframe, text="Cancel", command=self.destroy)

        bhelp.grid(row=0, column=0, sticky="w")
        bapply.grid(row=0, column=1, sticky="ns")
        bcancel.grid(row=0, column=2, sticky="e")

        hacframe.rowconfigure(0, weight=1)
        for i in range(3):
            hacframe.columnconfigure(i, weight=1)

        # Allow expansion
        self.config(padx=10, pady=5)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        for i in range(4):
            frame.rowconfigure(i, weight=1)
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=8)

        self.resizable(0, 0)

    def on_apply(self):
        # check for extension validity
        if not re.fullmatch(r"^\.[\w|\d]+", self.entry_ext.get()):
            messagebox.showerror(
                "Extension Error",
                "Extension can only have alphanumeric values and underscores.",
            )
            return

        # caveat: Python/Tk sets the dict's repr form, but this can easily
        # be solved with json's loads and dumps.
        logger.debug(f"Dumping config values into {self.__var} as json.")
        self.__var.set(
            json.dumps(
                dict(
                    extension=self.entry_ext.get(),
                    keylen=self.opt_klen.getvar("keylen"),
                    aesmode=self.opt_aesmode.getvar("aesmode"),
                    backend=self.opt_backend.getvar("backend"),
                ),
            ),
        )
        logger.debug(f"Destroying {self=}")
        self.destroy()


class Waitbox(tk.Toplevel):
    """Custom 'Please Wait' box to show during long running task."""

    def __init__(
        self, *args, master, operation, current=0, maximum=None, **kwargs
    ):
        super().__init__(*args, master=master, **kwargs)
        self._maximum = maximum
        self._current = current
        # 1. Waitbox message
        # 2. Progressbar
        # and some way to update the progressbar

        frame = ttk.Frame(self)
        frame.grid(row=0, column=0, sticky="ew")

        ttk.Label(
            frame,
            text=WAITBOX_MESSAGE.format(operation=operation),
        ).grid(row=0, column=0, sticky="new", padx=(0, 10))

        self._prg = ttk.Progressbar(frame, maximum=maximum, value=current)
        self._prg.grid(row=1, column=0, sticky="sew")

        # for the child widgets
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # overall window
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.config(padx=10, pady=10)

    def step(self, n=1):
        if self._current < (self._maximum or 100) - 1:
            self._prg.step(n)
            self._current += n


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

        self.rowconfigure(1, weight=1)  # expand the ARC buttons row-wise
        self.columnconfigure(0, weight=1)  # expand buttons columnwise
        self.columnconfigure(1, weight=1)  # expand buttons columnwise

        # some defaults
        self._keylen = 32
        self._backend = Backends.CRYPTOGRAPHY
        self._extension = ".pyflk"
        self._aesmode = modes.Modes.MODE_GCM

    def on_encrypt(self):
        """Encrypt everything in the listbox."""
        if not self._prepare("encrypt"):
            return
        self._submit_task("encrypt", True)

    def on_decrypt(self):
        """Decrypt everything in the listbox."""
        if not self._prepare("decrypt"):
            return
        self._submit_task("decrypt", False)

    def on_configure(self):
        var = tk.StringVar(self, name="config")
        top = SettingsPanel(
            var=var,
            master=self.master,
            keylen=self._keylen,
            extension=self._extension,
            backend=self._backend.name.title(),
            aesmode=self._aesmode.name,
        )
        logger.debug(f"Built SettingsPanel with {var=} for fetching values.")

        top.transient(self.master)
        top.focus_set()
        top.wait_visibility()
        top.grab_set()
        self.master.wait_window(top)

        if not var.get():  # cancelled operation, nothing to set.
            logger.debug("Operation was cancelled/exited. Nothing to set.")
            return

        config = json.loads(var.get())
        logger.debug(f"Received configuration {config=}")

        self._keylen = config["keylen"]
        self._backend = getattr(Backends, config["backend"].upper())
        self._extension = config["extension"]
        self._aesmode = getattr(modes.Modes, config["aesmode"].upper())

    def _build_waitbox(self, operation):
        """Create the waitbox that will be shown while the operation is in
        progress."""
        logger.debug(f"Building waitbox for {operation=}")

        waitbox = Waitbox(
            master=self.master,
            operation=operation,
            maximum=len(self._listbox.items),
        )
        waitbox.transient(self.master)
        waitbox.focus_set()
        waitbox.wait_visibility()
        waitbox.grab_set()
        return waitbox

    def _submit_task(self, operation, locking):
        """Starts the producer/consumer loop, while showing the waitbox.

        The producer is launched in a separate thread.
        The consumer loop updates any value pushed to the internal queue.
        """
        logger.debug("Starting producer-consumer loop...")
        # submit task to producer and let the consumer do its work
        q = deque()
        args = (locking, q)
        waitbox = self._build_waitbox(operation)
        Thread(target=self._producer, args=args).start()
        self._consumer(q, waitbox, operation)
        self.master.wait_window(waitbox)

    def _producer(self, locking, q):
        """Produces the filenames and their status and pushes it to the queue.

        This function runs in a separate thread, launched from `_submit_task`
        method. At the end of the operation, a snetinel value is sent to
        indicate the consumer loop that the task is done.
        """
        logger.debug(
            f"Setting up producer loop on thread={current_thread().name}"
        )

        for fname, fstat in parallel.files_locker(
            *self._listbox.items,
            password=self._entry_pwd.get().encode(),
            locking=locking,
            ext=self._extension,
            backend=self._backend,
        ):
            q.appendleft((fname, fstat))
        q.appendleft((_SENTINEL, _SENTINEL))

        logger.debug(
            f"Added sentinels {_SENTINEL} to queue. Producer loop will exit now."
        )

    def _consumer(self, q, waitbox, operation, _statdict=None):
        """Start the consumer loop.

        This function is called by `_submit_task` and runs in the *main thread*.
        After completion (upon recieving a sentinel value), the waitbox is
        destroyed and cleanup is performed.
        """
        if _statdict is None:
            _statdict = defaultdict(int)
            logger.debug(f"Made {_statdict=}. This will not be remade.")

        try:
            while True:
                fname, fstat = q.pop()
                if fname is _SENTINEL:
                    logger.debug(
                        "Received sentinel. Stopping producer-consumer loop."
                    )
                    # stop the task
                    waitbox.destroy()
                    self._cleanup(_statdict, operation)
                    break
                # keep updating
                waitbox.step()
                self._update(fname, fstat, _statdict)
        except IndexError:
            self.after(
                WAIT_TIME,
                self._consumer,
                q,
                waitbox,
                operation,
                _statdict,
            )

    def _update(self, fname, fstat, statdict):
        """Update the colors of listbox, count the files operated upon and
        don't let the master hang.
        """
        self._update_listbox_color(fname, fstat)
        statdict[fstat] += 1
        self.master.update()

    def _update_listbox_color(self, fname, fstat):
        """Updates the colors of listbox to show the operations performed
        visually.
        """
        # TODO: The colors can be set by the user as a part of the application
        # theme.
        idx = self._listbox.items.index(fname)
        if fstat == parallel.SUCCESS:
            self._listbox.itemconfig(idx, dict(bg="green"))
        elif fstat == parallel.FAILURE:
            self._listbox.itemconfig(idx, dict(bg="red"))
        elif fstat == parallel.INVALID:
            self._listbox.itemconfig(idx, dict(bg="purple", fg="yellow"))
        elif fstat == parallel.FILE_NOT_FOUND:
            self._listbox.itemconfig(idx, dict(bg="yellow", fg="black"))

    def _cleanup(self, statdict, operation):
        """Perform post-operation tasks."""
        logger.debug("The wait window has been destroyed. Updating master...")
        self.master.update()
        self._show_result(statdict, operation)

    def _show_result(self, statdict, operation):
        """Show the stats as a messagebox."""
        messagebox.showinfo(
            f"{operation.title()}ion results",
            f"The files have been {operation}ed",
            detail=RESULT_TEMPLATE.format(
                operation=operation.title(),
                success=statdict[parallel.SUCCESS],
                failure=statdict[parallel.FAILURE],
                file_not_found=statdict[parallel.FILE_NOT_FOUND],
                invalid=statdict[parallel.INVALID],
            ),
        )

    def _prepare(self, operation):
        """Perform pre-operation checks before starting the producer-consumer
        loop.
        """
        if not self._listbox.items:
            messagebox.showerror(
                "Error", f"No files selected for {operation}ion."
            )
            return
        elif not len(self._entry_pwd.get()):
            messagebox.showerror(
                "Error", f"No password entered for {operation}ion."
            )
            return
        elif len(self._entry_pwd.get()) < 8:
            messagebox.showerror(
                "Error", "Password must be greater than 8 bytes."
            )
            return
        else:
            logger.debug(f"All pre {operation}ion checks passed.")
            return True


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

        logger.debug(f"Building main application frame {self}")

        # pack with an internal padding otherwise the listbox will
        # look like shit.
        self._listbox.grid(
            row=0,
            column=0,
            ipadx=250,
            ipady=200,
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

        menu_file = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label="File", menu=menu_file)
        menu_file.add_command(label="Add", command=arcf.on_add)
        menu_file.add_command(label="Remove All", command=arcf.on_remove_all)
        menu_file.add_separator()
        menu_file.add_command(label="Configure...", command=encf.on_configure)

        menu_about = tk.Menu(menu, tearoff=False)
        menu.add_cascade(label="About", menu=menu_about)
        menu_about.add_command(
            label="About the App...",
            command=lambda: messagebox.showinfo(
                "About",
                "Pycryptor",
                detail=APP_DESC,
                parent=self,
            ),
        )
        menu_about.add_command(
            label="About Me...", command=lambda: webbrowser.open(ABOUT_ME)
        )
        menu_about.add_command(
            label="About AES...", command=lambda: webbrowser.open(AES_WIKI)
        )

        master.config(menu=menu)


def start_logging_with_flags():
    """Add logging capability with tunable verbosity."""
    logging_levels = {
        3: logging.WARNING,
        4: logging.INFO,
        5: logging.DEBUG,
    }

    ps = argparse.ArgumentParser(
        # only the package name is needed for `prog`
        prog=__loader__.name.split(".", 1)[0],
        description=APP_DESC,
        epilog=CLI_APP_EPILOG,
    )
    group = ps.add_mutually_exclusive_group()
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=3,
        help="Increase application verbosity."
        " This option is repeatable and will increase verbosity each time "
        "it is repeated."
        " This option cannot be used when -q/--quiet is used.",
    )

    group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Disable logging."
        " This option cannot be used when -v/--verbose is used.",
    )

    args = ps.parse_args()

    if args.quiet:
        return

    level = args.verbose
    if level >= 5:
        level = 5

    start_logging(logging_levels[level])


if __name__ == "__main__":
    start_logging_with_flags()  # enable logging
    logger.debug("Building application with grid manager.")

    root = tk.Tk()
    root.title("Pycryptor")
    cf = ControlFrame(master=root)
    cf.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    root.mainloop()
    logger.debug("Application destroyed without any errors.")
