import argparse         # Argument parsing
import os.path          # isfile() method
from tkinter import filedialog
import cv2

import tkinter as tk

from tkinter.simpledialog import Dialog

from PIL import Image
from tkinter import ttk

import snip

import traceback
from snip.tkit.contentcanvas import ContentCanvas

import dupedb

# from PIL import Image
# from tkinter import messagebox
# from snip import tkit
# from PIL import ImageTk
# import tkinter.font as tkFont
# import threading
# import glob             # File globbing


SHELVE_FILE_EXTENSIONS = ["json"]


def parse_args():
    """
    Parse args from command line and return the namespace

    Returns:
        TYPE: Description
    """
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "shelvefile", help="Database name")
    ap.add_argument(
        "-l", "--list", action="store_true",
        help="Show duplicate information on screen.")

    ap.add_argument(
        "--debug", action="store_true",
        help="Print debugging information for hashes.")
    ap.add_argument(
        "--verbose", action="store_true",
        help="Print additional information.")
    return ap.parse_args()


class Preloader(tk.Frame):

    """Frame that manages the sidebar and user input
    """

    # Init and window management

    def __init__(self, parent, *args, **kwargs):
        """Args:
            parent (tk): Tk parent widget
            *args: Passthrough
            **kwargs: Passthrough
        """
        tk.Frame.__init__(self, *args, **kwargs)

        self.controller = parent
        self.initwindow()

    def initwindow(self):
        pass


class ReplaceDialog(Dialog):

    def __init__(self, parent, hash, filelist, onDoOpCallback):
        self.filelist = filelist
        self.onDoOp = onDoOpCallback
        self.hash = hash
        super().__init__(parent=parent)

    def body(self, master):

        print(self.filelist)

        maxindex = len(self.filelist) - 1

        tk.Label(master, text="Source:").grid(column=0, row=0)
        self.picker_source = ttk.Combobox(master, values=self.filelist)
        self.picker_source.grid(column=1, row=0, sticky="ew")
        self.picker_source.current(min(0, maxindex))
        self.picker_source.focus()

        tk.Label(master, text="Target:").grid(column=0, row=1)
        self.picker_target = ttk.Combobox(master, values=self.filelist)
        self.picker_target.grid(column=1, row=1, sticky="ew")
        self.picker_target.current(min(1, maxindex))

        text_width = max(len(text) for text in self.filelist)
        self.picker_target.config(width=text_width)
        self.picker_source.config(width=text_width)

        master.columnconfigure(1, weight=1)
        master.pack(padx=5, pady=5, fill="x")

    def apply(self):
        source = self.picker_source.get()
        target = self.picker_target.get()

        assert not os.path.isdir(source)

        snip.filesystem.copyFileToDir(source, "undo", clobber=True)
        try:
            # Target doesn't have to exist
            snip.filesystem.copyFileToDir(target, "undo", clobber=True)
        except FileNotFoundError:
            pass

        if os.path.isdir(target):
            snip.filesystem.moveFileToDir(source, target, clobber=True)
        else:
            snip.filesystem.moveFileToFile(source, target, clobber=True)
        self.onDoOp(self.hash, source, target)


class MainWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        args = parse_args()

        self.initwindow()

        if not args.shelvefile:
            self.pick_and_open_shelvefile()
        else:
            self.open_shelvefile(args.shelvefile)

        # self.load_thread = threading.Thread(target=self.loadDuplicates)
        # self.load_thread.start()

        self.mainloop()

    def pick_and_open_shelvefile(self):
        self.open_shelvefile(
            os.path.splitext(
                os.path.split(
                    filedialog.askopenfilename()
                )[-1]
            )[0]
        )

    def refreshAfterOp(self, hash, source, target):
        if target not in self.duplicates[self.current_hash]:
            self.duplicates[hash].append(target)
        self.canvas.markCacheDirty(source)
        self.canvas.markCacheDirty(target)

    def open_shelvefile(self, shelvefile):
        if not shelvefile:
            return
        self.db = dupedb.db(shelvefile, bad_words=["Unsorted"], good_words=["Keep"])

        self.current_hash = ""

        self.current_file = tk.StringVar()
        self.current_file.set("")
        self.current_file.trace("w", self.onFileSelect)

        self.photoImageCache = {}
        self.current_filelist = []

        self.loadDuplicates()

    def initwindow(self):

        self.geometry("950x800")

        self.infobox = tk.Label(self)
        self.infobox.grid(column=1, row=0, sticky="ew")

        self.file_picker = tk.Frame(self, relief=tk.GROOVE)
        self.file_picker.grid(column=1, row=1, sticky="nsw")

        self.canvas = ContentCanvas(self, takefocus=True)
        self.canvas.grid(column=1, row=2, sticky="nsew")
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        self.bind("<Right>", self.nextHash)
        self.bind("<Down>", self.nextImage)
        self.bind("<Left>", self.prevHash)
        self.bind("<Up>", self.prevImage)

        self.bind("<d>", self.on_btn_delete)
        self.bind("<a>", self.on_btn_undo)
        self.bind("<r>", self.on_btn_replace)
        self.bind("<c>", self.on_btn_concat)

        self.canvas.focus()

        self.toolbar = tk.Frame(self)
        self.toolbar.grid(column=0, row=0, rowspan=3, sticky="ns")

        inOrderRow = 0

        def rowInOrder():
            """Helper function to increment in-order elements"""
            nonlocal inOrderRow
            inOrderRow += 1
            return inOrderRow

        self.hash_picker = ttk.Combobox(self.toolbar, state="readonly", takefocus=False)
        self.hash_picker.bind("<<ComboboxSelected>>", self.onHashSelect)
        self.hash_picker.grid(column=0, row=rowInOrder(), sticky="ew")

        btn_open = ttk.Button(self.toolbar, text="Open", takefocus=False, command=self.pick_and_open_shelvefile)
        btn_delete = ttk.Button(self.toolbar, text="Delete", takefocus=False, command=self.on_btn_delete)
        btn_replace = ttk.Button(self.toolbar, text="Replace", takefocus=False, command=self.on_btn_replace)
        btn_concat = ttk.Button(self.toolbar, text="Concatenate", takefocus=False, command=self.on_btn_concat)

        self.var_progbar_prog = tk.IntVar()
        self.progbar_prog = ttk.Progressbar(self.toolbar, variable=self.var_progbar_prog)

        for btn in [btn_open, btn_delete, btn_replace, btn_concat, self.progbar_prog]:
            btn.grid(row=rowInOrder(), sticky="ew")

    def update_infobox(self):
        filepath = self.current_file.get()
        filename = os.path.split(filepath)[1]
        filesize = snip.strings.bytes_to_string(os.path.getsize(filepath))
        try:
            frames = snip.image.framesInImage(filepath)
            w, h = Image.open(filepath).size
            newtext = f"{filename} [{frames}f]\n{filesize} [{w}x{h}px]"
        except Exception:
            newtext = f"{filename} \n{filesize}"
            # traceback.print_exc()
        self.infobox.configure(text=newtext)

    # Navigate

    def nextImage(self, *args):
        return self.modImage(1)

    def prevImage(self, *args):
        return self.modImage(-1)

    def modImage(self, mod):
        next_image_index = self.current_filelist.index(self.current_file.get()) + mod
        next_image = self.current_filelist[next_image_index % len(self.current_filelist)]
        self.current_file.set(next_image)

    def nextHash(self, *args):
        return self.modHash(1)

    def prevHash(self, *args):
        return self.modHash(-1)

    def modHash(self, mod):
        try:
            self.hash_picker.current(newindex=self.hash_picker.current() + mod)
        except tk.TclError:
            self.bell()
        self.onHashSelect()

    # Process actions
    def on_btn_undo(self, event=None):
        undopath = TRASH.undo()
        if undopath:
            self.canvas.markCacheDirty(undopath)
        self.onHashSelect()

    def on_btn_delete(self, event=None):
        filepath = self.current_file.get()
        TRASH.delete(filepath)
        self.canvas.markCacheDirty(filepath)
        self.onHashSelect()

    def on_btn_replace(self, event=None):
        permutations = [
            os.path.join(
                os.path.dirname(p), 
                os.path.splitext(p)[0] + "-alt" + os.path.splitext(p)[1]
            ) for p in self.current_filelist
        ]
        filelist = self.current_filelist + permutations        
        ReplaceDialog(self, self.current_hash, filelist, self.refreshAfterOp)
        self.onHashSelect()
        self.after(20, self.canvas.focus)

    def on_btn_concat(self, event=None):
        images = [cv2.imread(path) for path in self.current_filelist]
        height, width, __ = images[0].shape

        concat = (cv2.vconcat(images) if width > height else cv2.hconcat(images))

        newFileName = os.path.normpath(filedialog.asksaveasfilename(
            initialdir=os.path.split(self.current_file.get())[0],
            initialfile=f"{self.current_hash}_concat.jpg"
        ))

        if newFileName == ".":
            return

        cv2.imwrite(newFileName, concat)
        self.duplicates[self.current_hash].append(newFileName)
        self.onHashSelect()

    # Load and select

    def loadDuplicates(self):
        generator = self.db.generateDuplicateFilelists(bundleHash=True, threshhold=2)
        self.duplicates = {}
        for (sorted_filenames, bundled_hash) in generator:
            self.duplicates[bundled_hash] = sorted_filenames
            # if len(self.duplicates.keys()) > 5:
            #     break

        self.hash_picker.configure(values=list(self.duplicates.keys()))
        self.hash_picker.current(0)
        self.progbar_prog.configure(maximum=len(list(self.duplicates.keys())))
        self.onHashSelect()

    def onFileSelect(self, *args):
        new_file = self.current_file.get()
        # print("Switch file", new_file)
        self.canvas.setFile(new_file)
        self.update_infobox()

    def onHashSelect(self, *args):
        self.current_hash = self.hash_picker.get()
        self.var_progbar_prog.set(self.hash_picker.current())
        # print("Switch hash", new_hash)

        for widget in self.file_picker.winfo_children():
            widget.destroy()

        set_first_file = True
        self.current_file.set(None)
        self.current_filelist = list(filter(TRASH.isfile, self.duplicates[self.current_hash]))
        # self.listbox_images.delete(0, self.listbox_images.size())
        for filename in self.current_filelist:
            tk.Radiobutton(
                self.file_picker,
                text=filename,
                variable=self.current_file,
                value=filename
            ).pack(anchor="w")

            if set_first_file:
                self.current_file.set(filename)
                set_first_file = False


if __name__ == "__main__":
    try:
        global TRASH
        with snip.filesystem.Trash(verbose=True) as TRASH:
            MainWindow()
    except KeyboardInterrupt:
        traceback.print_exc()
        raise
