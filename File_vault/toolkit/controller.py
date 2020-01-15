from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.font import Font

from . import utility as util
from .fileslocker import files_locker


class Controller:
    """
    This controls the behavior of Listbox and Encrypt/Decrypt
    button. It also displays the message with respect to the context.
    """
    def __init__(self, file_items, tk_listbox, parent=None):
        self.parent = parent
        self.file_items = file_items
        self.tk_listbox = tk_listbox
        self.error = ""
        self.stat_template = """Here are the results after {method}ion:

        Files {method}ed: {success}
            Files failed: {failed}
         Files not found: {fnf}
           Files ignored: {ign}
            """

    def add(self):
        """
        Adds file to list.
        """
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        elif file_path not in self.file_items:
            self.tk_listbox.insert(len(self.file_items) + 1, file_path)
            self.file_items.append(file_path)

    def remove(self):
        """
        Removes file from list.
        """
        try:
            index = self.tk_listbox.curselection()[0]
            del self.file_items[index]
            self.tk_listbox.delete(self.tk_listbox.curselection()[0])
        except IndexError:
            messagebox.showerror("Error", "No files selected.")

    def encrypt(self, password, ext, dklen, backend):
        """
        Starts encryption process.
        """
        self._submit_task(
            self.file_items,
            password,
            mode="encrypt",
            ext=ext,
            dklen=dklen,
            backend=backend,
            method="encrypt",
        )

    def decrypt(self, password, ext, dklen, backend):
        """
        Starts decryption process.
        """
        self._submit_task(
            self.file_items,
            password,
            mode="decrypt",
            ext=ext,
            dklen=dklen,
            backend=backend,
            method="decrypt",
        )

    def _submit_task(self, file_items, password, **kwargs):
        """
        The task is submitted here.
        A thread is started which calls the required function.

        Callbacks are added to the `Future` object to perform the
        cleanup after the task is completed.
        """
        if self._prepare(self.file_items, password, kwargs['method']):
            with ThreadPoolExecutor(1) as exc:
                # Initiate the `waitbox` and set a callback by default.
                _wbox = self._waitbox(kwargs['method'])
                result = exc.submit(files_locker, file_items, password,
                                    **kwargs)

                # add all callbacks to the futures.
                result.add_done_callback(lambda x: _wbox.destroy())
                # this callback restores the default behavior of `self.parent`
                result.add_done_callback(lambda x: self.parent.protocol(
                    'WM_DELETE_WINDOW', self.parent.destroy))
                result.add_done_callback(lambda x: self._show_result(
                    result.result(), kwargs['mode']))

                # Start the Waitbox
                try:
                    _wbox.focus_set()
                    _wbox.grab_set()
                    _wbox.transient(self.parent)
                    _wbox.mainloop()
                except tk.TclError:
                    pass

    def _show_result(self, stats, method):
        """
        Shows the result of the task after its completion as a message box.
        Also the colors of Listbox are updated according to color-code.
        """
        not_found, success, failure, inv = (
            stats["FNF"],
            stats["SUC"],
            stats["FAIL"],
            stats["INV"],
        )

        tk_list_items = self.tk_listbox.getvar(
            self.tk_listbox.cget("listvariable"))

        for each in tk_list_items:
            index = self.tk_listbox.get(0, "end").index(each)
            if each in success:
                self.tk_listbox.itemconfig(index, {"bg": "green"})
            elif each in failure:
                self.tk_listbox.itemconfig(index, {"bg": "red"})
            elif each in inv:
                self.tk_listbox.itemconfig(index, {
                    "bg": "purple",
                    "fg": "white"
                })
            elif each in not_found:
                self.tk_listbox.itemconfig(index, {
                    "bg": "yellow",
                    "fg": "black"
                })

        messagebox.showinfo(
            f"{method.title()}ed",
            self.stat_template.format(
                method=method,
                success=len(success),
                failed=len(failure),
                fnf=len(not_found),
                ign=len(inv),
            ),
        )

    def _prepare(self, file_items, password, method):
        """
        This function checks for any user's error before proceeding.
        Returns False if error is found.

        Any user side error is reported as an Error message.
        """
        # general errors
        if not len(file_items):
            messagebox.showerror(
                "Error", "No files has been selected "
                f"for {method}ion.")
            return
        elif not len(password):
            messagebox.showerror("Error",
                                 f"No password entered for {method}ion.")
            return
        elif len(password) < 8:
            messagebox.showerror("Error",
                                 "Password must be greater than 8 bytes.")
            return
        # all correct...
        else:
            return True

    def _waitbox(self, method):
        """
        Creates a waitbox while the app is running.
        This prevents the app from hanging. (call it a cool hack or whatever)
        """
        font = Font(size=14, weight='bold')
        top = tk.Toplevel(self.parent)
        tk.Label(
            top,
            text=util.waitbox_msg.format(method=method),
            font=font
        ).pack(anchor='center')
        top.title("Please wait...")
        top.resizable(0, 0)

        # Cannot destroy windows manually while program is running
        top.protocol('WM_DELETE_WINDOW', lambda: None)
        self.parent.protocol('WM_DELETE_WINDOW', lambda: None)
        return top
