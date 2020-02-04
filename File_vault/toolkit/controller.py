import threading
import queue

from tkinter import filedialog, messagebox, ttk, Toplevel, Frame

from .utils import messages
from .fileslocker import files_locker


class Controller:
    """
    This controls the behavior of Listbox and Encrypt/Decrypt
    button. It also displays the message with respect to the context.
    """
    _result_queue = queue.Queue(1)
    wait_time = 250

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
            self.tk_listbox.delete(index)
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

    def _produce_task(self, file_items, password, _wbox, **kwargs):
        # put the result, waitbox widget and task-method in a queue.
        # This is a blocking code.
        self._result_queue.put_nowait(
            (files_locker(file_items, password,
                          **kwargs), _wbox, kwargs['method']))

    def _submit_task(self, file_items, password, **kwargs):
        """
        The task is submitted here.
        A thread is started which calls the required function.

        Works on producer-consumer model.
        """
        if self._prepare(self.file_items, password, kwargs['method']):
            _wbox = self._waitbox(kwargs['method'])

            # create a producer thread and run in parallel
            threading.Thread(target=lambda: self._produce_task(
                file_items, password, _wbox, **kwargs)).start()

            # start the consumer and the waitbox.
            self._consume_task()
            _wbox.mainloop()

    def _consume_task(self):
        try:
            # try to fetch the values
            result, _wbox, method = self._result_queue.get_nowait()
        except queue.Empty:
            # let parent widget call it again after `wait_time`
            self.parent.after(self.wait_time, self._consume_task)
        else:
            # cleanup after task is done
            self._cleanup(result, _wbox, method)

    def _cleanup(self, result, _wbox, method):
        """
        This is called only after the thread has finished it's task.
        """
        # The waitbox widget is destroyed,
        # the parent's behavior is restored, and the result is shown.
        _wbox.destroy()
        self.parent.update()
        self.parent.protocol('WM_DELETE_WINDOW', self.parent.destroy)
        self._show_result(result, method)

    def _show_result(self, stats, method):
        """
        Shows the result of the task after its completion as a message box.
        Also the colors of Listbox are updated according to color-code.

        This must always be called by the main thread!
        """
        not_found, success, failure, inv = (
            stats["FNF"],
            stats["SUC"],
            stats["FAIL"],
            stats["INV"],
        )

        for each in iter(self.file_items):
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
            ))

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
        This prevents the app from hanging.
        """
        # Basic tasks to set up the waitbox Toplevel widget.
        top = Toplevel(self.parent)
        top.title("Please wait...")
        top.resizable(0, 0)
        fr = Frame(top)
        fr.pack()

        # pack the Label with the correct working mode.
        ttk.Label(
            fr,
            text=messages.waitbox_msg.format(method=method),
        ).pack(anchor='center')

        if self.parent.iconname() is not None:
            top.iconbitmap(self.parent.iconname())

        # User cannot destroy windows manually while program is running
        top.protocol('WM_DELETE_WINDOW', lambda: None)
        self.parent.protocol('WM_DELETE_WINDOW', lambda: None)
        top.transient(self.parent)
        top.focus_set()
        top.grab_set()
        return top
