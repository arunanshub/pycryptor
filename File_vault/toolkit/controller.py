import threading
import queue

from tkinter import filedialog, messagebox, ttk, Toplevel, Frame

from .utils import messages
from . import fileslocker as flocker


class Controller:
    """
    This controls the behavior of Listbox and Encrypt/Decrypt
    button. It also displays the message with respect to the context.
    """
    _result_queue = queue.Queue()
    wait_time = 250
    _sentinel = object()
    _stat_counter = dict()

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
        file_path = filedialog.askopenfilenames()
        if not file_path:
            return
        for each in file_path:
            if each not in self.file_items:
                self.tk_listbox.insert('end', each)
                self.file_items.append(each)

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

    def remove_all(self):
        self.tk_listbox.delete(0, 'end')
        self.file_items.clear()

    def encrypt(self, password, ext, dklen, backend):
        """
        Starts encryption process.
        """
        self._submit_task(
            self.file_items,
            password,
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
            ext=ext,
            dklen=dklen,
            backend=backend,
            method="decrypt",
        )

    def _produce_task(self, file_items, password, _wbox, lock, **kwargs):
        """
        Puts the result tuple, waitbox widget and task-method in a queue.
        This is a blocking code and runs in a thread.
        """
        for file_res in flocker.files_locker(*file_items,
                                             password=password,
                                             lock=lock,
                                             **kwargs):
            # put the (filename, result, waitbox-variable, method) in the
            # result queue.
            self._result_queue.put_nowait((
                *file_res,
                _wbox,
                kwargs['method'],
            ))
        self._result_queue.put_nowait((self._sentinel, ) * 2 +
                                      (_wbox, kwargs['method']))

    def _submit_task(self, file_items, password, **kwargs):
        """
        The task is submitted here.
        A thread is started which calls the required function.

        Works on producer-consumer model.
        """
        if self._prepare(self.file_items, password, kwargs['method']):
            _wbox = self._waitbox(kwargs['method'])
            lock = True if kwargs['method'] == 'encrypt' else False

            # create a producer thread and run in parallel
            threading.Thread(target=lambda: self._produce_task(
                file_items, password, _wbox, lock=lock, **kwargs)).start()

            # start the consumer and the waitbox.
            self._consume_task()
            _wbox.mainloop()

    def _consume_task(self):
        """The consumer function.
        This function is called periodically to check for results, which
        were put into the `_result_queue` by the producer thread.

        A sentinel object is used for shutting down the operation and
        showing the results.
        """
        _call_later = lambda: self.parent.after(self.wait_time, self.
                                                _consume_task)
        try:
            while True:
                file, result, _wbox, method = self._result_queue.get_nowait()
                if file is self._sentinel:
                    self._cleanup(self._stat_counter, _wbox, method)
                    self._stat_counter.clear()
                    break
                else:
                    self._gradual_update(file, self._stat_counter, result)
        except queue.Empty:
            # let parent widget call it again after `wait_time`
            _call_later()

    def _gradual_update(self, file, stat_dict, result):
        """
        Gradually increase the counters for their respective modes
        and change the `ListBox`'s color.
        """
        self._change_listbox_color(file, result)
        stat_dict.setdefault(result, 0)
        stat_dict[result] += 1
        self.parent.update()

    def _cleanup(self, stat_dict, _wbox, method):
        """
        This is called only after the thread has finished it's task.
        """
        # The waitbox widget is destroyed,
        # the parent's behavior is restored,
        # and the result is shown.
        _wbox.destroy()
        self.parent.update()
        self.parent.protocol('WM_DELETE_WINDOW', self.parent.destroy)
        self._show_msgbox_result(stat_dict, method)

    def _show_msgbox_result(self, stat_dict, method):
        """
        Display the stats to the user after the task is done.
        Called from the MainThread.
        """
        messagebox.showinfo(
            f"{method.title()}ed",
            self.stat_template.format(
                method=method,
                success=stat_dict.get(flocker.SUCCESS, 0),
                failed=stat_dict.get(flocker.FAILURE, 0),
                fnf=stat_dict.get(flocker.FILE_NOT_FOUND, 0),
                ign=stat_dict.get(flocker.INVALID, 0),
            ))

    def _change_listbox_color(self, file, result):
        index = self.tk_listbox.get(0, "end").index(file)
        if result == flocker.SUCCESS:
            self.tk_listbox.itemconfig(index, {"bg": "green"})
        elif result == flocker.FAILURE:
            self.tk_listbox.itemconfig(index, {"bg": "red"})
        elif result == flocker.INVALID:
            self.tk_listbox.itemconfig(index, {"bg": "purple", "fg": "white"})
        elif result == flocker.FILE_NOT_FOUND:
            self.tk_listbox.itemconfig(index, {"bg": "yellow", "fg": "black"})

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
