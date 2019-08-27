from collections import deque
from tkinter import filedialog, messagebox

# import threading
from pycryptor_tools.thread_locker import thread_locker


class Controller:

    def __init__(self, file_items, tk_listbox):
        self.file_items = file_items
        self.tk_listbox = tk_listbox
        self.error = ""
        self.stat_template = """Here are the results after {method}ion:
        
        Files {method}ed: {success}
            Files failed: {failed}
         Files not found: {fnf}
           Files ignored: {ign}
            """

    # adds file to list
    def add(self):
        file_path = filedialog.askopenfilename()
        if file_path is '':
            return
        if file_path not in self.file_items:
            self.tk_listbox.insert(len(self.file_items) + 1, file_path)
            self.file_items.append(file_path)

    # removes file from list
    def remove(self):
        try:
            index = self.tk_listbox.curselection()[0]
            del self.file_items[index]
            self.tk_listbox.delete(self.tk_listbox.curselection()[0])

        except IndexError:
            messagebox.showerror("Error", "No files selected.")

    # starts encryption process
    def encrypt(self, password, ext, dklen):

        # general errors
        if len(self.file_items) == 0:
            messagebox.showerror("Error", "No file has been selected for encryption.")
            return

        elif len(password) == 0:
            messagebox.showerror("Error", "No password entered for encryption.")
            return
        else:
            stats = thread_locker(self.file_items, password.encode(), 'encrypt', ext=ext, dklen=dklen)
            not_found, success, failure, inv = stats['FNF'], stats['SUC'], stats['FAIL'], stats['INV']

            tk_list_items = self.tk_listbox.getvar(self.tk_listbox.cget('listvariable'))

            for each in tk_list_items:
                index = self.tk_listbox.get(0, 'end').index(each)
                if each in success:
                    self.tk_listbox.itemconfig(index, {"bg": 'green'})
                elif each in failure:
                    self.tk_listbox.itemconfig(index, {"bg": 'red'})
                elif each in inv:
                    self.tk_listbox.itemconfig(index, {"bg": 'purple', 'fg': 'white'})
                elif each in not_found:
                    self.tk_listbox.itemconfig(index, {"bg": 'yellow', 'fg': 'black'})

            messagebox.showinfo('Encrypted', self.stat_template.format(
                method='encrypt',
                success=len(success),
                failed=len(failure),
                fnf=len(not_found),
                ign=len(inv)
            ))

    # starts decryption process
    def decrypt(self, password, ext, dklen):

        # general errors
        if len(self.file_items) == 0:
            messagebox.showerror("Error", "No files has been selected for decryption.")

        elif len(password) == 0:
            messagebox.showerror("Error", "No password entered for decryption.")
            return

        else:
            stats = thread_locker(self.file_items, password.encode(), 'decrypt', ext=ext, dklen=dklen)

            not_found, success, failure, inv = stats['FNF'], stats['SUC'], stats['FAIL'], stats['INV']

            tk_list_items = self.tk_listbox.getvar(self.tk_listbox.cget('listvariable'))

            for each in tk_list_items:
                index = self.tk_listbox.get(0, 'end').index(each)
                if each in success:
                    self.tk_listbox.itemconfig(index, {"bg": 'green'})
                elif each in failure:
                    self.tk_listbox.itemconfig(index, {"bg": 'red'})
                elif each in inv:
                    self.tk_listbox.itemconfig(index, {"bg": 'purple', "fg": 'white'})
                elif each in not_found:
                    self.tk_listbox.itemconfig(index, {"bg": 'yellow', "fg": 'black'})

            messagebox.showinfo('Decrypted', self.stat_template.format(
                method='decrypt',
                success=len(success),
                failed=len(failure),
                fnf=len(not_found),
                ign=len(inv)
            ))
