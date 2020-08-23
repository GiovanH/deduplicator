import argparse         # Argument parsing
import os.path          # isfile() method
from tkinter import filedialog
import cv2

import tkinter as tk
from tkinter import messagebox
from _tkinter import TclError

from PIL import Image
from tkinter import ttk

import snip
from snip import tkit

import traceback
from snip.tkit.contentcanvas import ContentCanvas

import dupedb
from dedupc import makeSortTupleAll, explainSort

import functools
import re
from pathlib import Path

match_exts = [".jpg", ".gif", ".webm", ".png"]

# from PIL import Image
# from tkinter import messagebox
# from snip import tkit
# from PIL import ImageTk
# import tkinter.font as tkFont
# import threading
# import glob             # File globbing

from snip.stream import TriadLogger
logger = TriadLogger(__name__)

SHELVE_FILE_EXTENSIONS = ["json"]


def parse_args():
    """Parse args from command line and return the namespace.

    Returns
        TYPE: Description
    """
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "shelvefile", help="Database name")

    ap.add_argument(
        "--threshhold", default=2, type=int, help="Min number of duplicates")
    ap.add_argument(
        "--good_dirs", nargs='+', default=[],
        help="Substrings in the path to penalize during file sorting.")
    ap.add_argument(
        "--bad_dirs", nargs='+', default=[],
        help="Substrings in the path to prioritize during file sorting.")
    ap.add_argument(
        "--good_names", nargs='+', default=[],
        help="Substrings in the path to penalize during file sorting.")
    ap.add_argument(
        "--bad_names", nargs='+', default=[],
        help="Substrings in the path to prioritize during file sorting.")
    return ap.parse_args()

def getSeriesInfo(name):
    from collections import namedtuple
    patterns = [
        (r"_0(\d)_1$",    "_0<#>_1"),    # Patreon
        (r"o(\d+)_1280$", "o<#>_1280"),  # Tumblr
        (r"_(\d+)$",      "_<#>"),
        (r"\((\d+)\)$",   "(<#>)"),
        (r"_p(\d+)$",     "_p<#>"),
        (r"_img(\d+)$",   "_img<#>"),
        (r"-img(\d+)$",   "-img<#>"),
        (r"-alt(\d*)$",   "-alt<#>"),
        (r" edit()$",     " edit<#>"),
    ]
    for (pattern, stylem) in patterns:
        match = re.search(pattern, name)
        if match:
            try:
                i = int(match.groups()[0])
            except ValueError:
                i = 1
            if i > 1000:
                continue
            style = re.sub(pattern, stylem, name)
            return namedtuple('SeriesInfo', ["no", "style"])(i, style)

    return None

def altPathOf(path):
    dirname = os.path.dirname(path)
    stem, ext = os.path.splitext(path)

    seriesinfo = getSeriesInfo(stem)
    if seriesinfo:
        i = seriesinfo.no
        style = seriesinfo.style
    else:
        i = 1
        style = stem + "_<#>"

    working_path = os.path.join(
        dirname,
        f"{style.replace('<#>', str(i))}{ext}"
    )
    while working_path == path or os.path.isfile(working_path):
        i += 1
        working_path = os.path.join(
            dirname,
            f"{style.replace('<#>', str(i))}{ext}"
        )
        assert i < 100
    return working_path

def findBaseFileForPath(path):
    name = os.path.splitext(path)[0]

    seriesinfo = getSeriesInfo(name)
    if not seriesinfo:
        return False

    i, style = seriesinfo
    base_name = style.replace("<#>", str(i - 1))
    return any(base_name != name and os.path.isfile(base_name + ext)
        for ext in match_exts)


class MainWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:

            args = parse_args()

            self.criteria = {
                "good_names": frozenset(args.good_names),
                "bad_names": frozenset(args.bad_names),
                "good_dirs": frozenset(args.good_dirs),
                "bad_dirs": frozenset(args.bad_dirs),
            }

            self.threshhold = args.threshhold

            self.initwindow()

            try:
                if not args.shelvefile:
                    self.pick_and_open_shelvefile()
                else:
                    self.open_shelvefile(args.shelvefile)
            except TclError:
                logger.error("No duplicate images in selection.")
                self.destroy()
                return

            # self.load_thread = threading.Thread(target=self.loadDuplicates)
            # self.load_thread.start()

            self.mainloop()
        except KeyboardInterrupt:
            print("Window init aborted")
            self.destroy()

    def pick_and_open_shelvefile(self):
        self.open_shelvefile(
            os.path.splitext(
                os.path.split(
                    filedialog.askopenfilename()
                )[-1]
            )[0]
        )

    def open_shelvefile(self, shelvefile):
        if not shelvefile:
            return
        self.db = dupedb.db(shelvefile)
        self.trash = snip.filesystem.Trash(verbose=True)

        self.current_hash = ""

        self.current_file = tk.StringVar()
        self.current_file.set("")
        self.current_file.trace("w", self.onFileSelect)

        self.current_filelist = []

        self.loadDuplicates()

    def destroy(self):
        self.trash.finish()
        super().destroy()

    def initwindow(self):

        self.geometry("950x800")

        self.infobox = tk.Label(self)
        self.infobox.grid(column=1, row=0, sticky="ew")

        self.file_picker = tk.Frame(self, relief=tk.GROOVE)
        self.file_picker.grid(column=1, row=1, sticky="nsw")
        # Minimium size here to avoid some expensive canvas resizing
        self.grid_rowconfigure(1, minsize=82)

        self.canvas = ContentCanvas(self, takefocus=True)
        self.canvas.grid(column=1, row=2, sticky="nsew")
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        self.bind("<Right>", self.nextHash)
        self.bind("<Down>", self.nextImage)
        self.bind("<Left>", self.prevHash)
        self.bind("<Up>", self.prevImage)

        self.bind("<d>", self.on_btn_delete)
        self.bind("1", self.on_btn_delete)
        self.bind("<Delete>", self.on_btn_delete)
        self.bind("<a>", self.on_btn_undo)
        self.bind("2", self.on_btn_delete)
        self.bind("<Control-z>", self.on_btn_undo)
        self.bind("<m>", self.on_btn_move)
        self.bind("<w>", self.on_btn_move)
        self.bind("<r>", self.on_btn_replace)
        self.bind("<c>", self.on_btn_concat)

        self.bind("<s>", self.on_btn_superdelete)
        self.bind("<0>", self.on_btn_superdelete)

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
        btn_move = ttk.Button(self.toolbar, text="Move", takefocus=False, command=self.on_btn_move)
        btn_replace = ttk.Button(self.toolbar, text="Replace", takefocus=False, command=self.on_btn_replace)
        self.btn_concat = btn_concat = ttk.Button(self.toolbar, text="Concatenate", takefocus=False, command=self.on_btn_concat)

        self.opt_hidealts_var = tk.BooleanVar(value=False)
        opt_hidealts = ttk.Checkbutton(self.toolbar, text="Hide known alts", variable=self.opt_hidealts_var)
        self.opt_hidealts_var.trace("w", lambda *a: self.loadDuplicates())

        self.var_progbar_seek = tk.IntVar()
        self.progbar_seek = ttk.Scale(self.toolbar, takefocus=False, variable=self.var_progbar_seek, command=self.on_adjust_seek)

        for btn in [btn_open, btn_delete, btn_move, btn_replace, btn_concat, opt_hidealts, self.progbar_seek]:
            btn.grid(row=rowInOrder(), sticky="ew")

    def on_adjust_seek(self, event):
        self.hash_picker.current(newindex=int(float(event)))
        self.onHashSelect()

    def update_infobox(self):
        filepath = self.current_file.get()
        if not filepath:
            return

        filename = os.path.split(filepath)[1]
        filesize = os.path.getsize(filepath)
        filesize_str = snip.strings.bytes_to_string(filesize)
        try:
            frames = snip.image.framesInImage(filepath)
            w, h = Image.open(filepath).size
            ratio = filesize / (w * h)
            newtext = f"{filename} [{frames}f]\n{filesize_str} [{w}x{h}px] [{ratio}]"
        except Exception:
            newtext = f"{filename} \n{filesize_str}"
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

    def currentFilelistRelative(self):
        filelist = self.current_filelist
        current_index = self.current_filelist.index(self.current_file.get())
        rotated = filelist[current_index:] + filelist[:current_index]
        # logger.debug(f"Rotating filelist by {current_index}")
        # logger.debug(filelist)
        # logger.debug(rotated)
        return rotated

    def on_btn_undo(self, event=None):
        undopath = self.trash.undo()
        if undopath:
            self.canvas.markCacheDirty(undopath)
        self.onHashSelect()

    def on_btn_delete(self, event=None):
        filepath = self.current_file.get()
        self.trash.delete(filepath)
        self.canvas.markCacheDirty(filepath)
        self.onHashSelect()

    def on_btn_superdelete(self, event=None):
        from dedupc import _doSuperDelete

        current_hash = self.hash_picker.get()
        filelist = self.current_filelist

        explanation = tk.StringVar(self)
        _doSuperDelete(filelist, current_hash, self.trash.delete, criteria=self.criteria, mock=True, explain=explanation.set)

        should_do = True or messagebox.askyesno(
            title="Confirm",
            message=f"Do superdelete operation?\n{explanation.get()}"
        )
        if should_do is True:
            new_file = _doSuperDelete(filelist, current_hash, self.trash.delete, criteria=self.criteria, mock=False)
            if new_file not in filelist:
                self.duplicates[current_hash].append(new_file)

        for f in filelist:
            self.canvas.markCacheDirty(f)
        self.nextHash()

    def on_btn_replace(self, event=None):
        current_filelist_relative = self.currentFilelistRelative()
        permutations = [
            altPathOf(p) for p in current_filelist_relative
        ]
        target_paths = [current_filelist_relative, permutations + current_filelist_relative]
        results = tkit.MultiSelectDialog(
            self,
            ["Source: ", "Target: "],
            target_paths,
            stagger_lists=True
        ).results

        if results:
            source, target = results

            target_fixed = os.path.splitext(target)[0] + os.path.splitext(source)[1]

            snip.filesystem.moveFileToFile(source, target_fixed, clobber=True)
            logger.debug("replace '%s' --> '%s'", source, target_fixed)

            if target_fixed != target:
                self.trash.delete(target)
                self.canvas.markCacheDirty(target)

            if target_fixed not in self.duplicates[self.current_hash]:
                self.duplicates[self.current_hash].append(target_fixed)
            self.canvas.markCacheDirty(source)
            self.canvas.markCacheDirty(target_fixed)

            self.onHashSelect()
        self.after(20, self.canvas.focus)

    def on_btn_move(self, event=None):
        current_filelist_relative = self.currentFilelistRelative()
        new_directory_choices = list(
            set(os.path.dirname(p) for p in current_filelist_relative).union(
                os.path.dirname(os.path.dirname(p)) for p in current_filelist_relative)
        )

        default_new_directory = os.path.dirname(current_filelist_relative[min(1, len(current_filelist_relative) - 1)])

        new_directory_choices.remove(default_new_directory)
        new_directory_choices.insert(0, default_new_directory)

        results = tkit.MultiSelectDialog(
            self,
            ["Source: ", "New directory: "],
            [
                current_filelist_relative,
                new_directory_choices
            ],
            stagger_lists=False
        ).results

        if results:
            source, target = results

            if not os.path.isdir(target):
                os.makedirs(target)

            new_path = snip.filesystem.moveFileToDir(source, target, clobber=False)
            logger.debug("move '%s' --> '%s'", source, target)

            self.duplicates[self.current_hash].append(new_path)

            self.onHashSelect()
        self.after(20, self.canvas.focus)

    def on_btn_concat(self, event=None):
        current_filelist_relative = self.currentFilelistRelative()
        images = [cv2.imread(path) for path in current_filelist_relative]
        height, width, __ = images[0].shape

        concat = (cv2.vconcat(images) if width > height else cv2.hconcat(images))

        current_file_dir, current_file = os.path.split(self.current_file.get())
        simple_name, __ = os.path.splitext(current_file)

        newFileName = os.path.normpath(filedialog.asksaveasfilename(
            initialdir=current_file_dir,
            initialfile=f"{simple_name}_concat.jpg"
        ))

        if newFileName == ".":
            return

        logger.debug("concatinating '%s' to '%s' with method '%s'", current_filelist_relative, newFileName, concat)

        cv2.imwrite(newFileName, concat)
        self.duplicates[self.current_hash].append(newFileName)
        self.onHashSelect()

    # Load and select

    def loadDuplicates(self):

        generator = self.db.generateDuplicateFilelists(bundleHash=True, threshhold=self.threshhold, validate=True)
        self.duplicates = {}
        for (filelist, bundled_hash) in generator:
            if self.opt_hidealts_var.get():
                # noextlist = {os.path.splitext(p)[0] for p in filelist}
                for filename in filelist.copy():
                    base_name = findBaseFileForPath(filename)
                    if base_name:
                        logger.info(f"{filename} has base file in {base_name}")
                        filelist.remove(filename)
                    # else:
                    #     logger.info(f"{filename} has NO base file in {base_names}")
                if len(filelist) < self.threshhold:
                    continue
            self.duplicates[bundled_hash] = filelist
            # if len(self.duplicates.keys()) > 5:
            #     break
        self.duplicate_hash_list = list(self.duplicates.keys())
        self.hash_picker.configure(values=self.duplicate_hash_list)
        self.hash_picker.current(0)
        self.progbar_seek.configure(to=len(self.duplicate_hash_list))
        self.onHashSelect()

    def onFileSelect(self, *args):
        new_file = self.current_file.get()
        # logger.debug("Switch file to '%s'", new_file)
        self.canvas.setFile(new_file)
        self.update_infobox()

    def onHashSelect(self, *args):
        self.current_hash = self.hash_picker.get()
        self.var_progbar_seek.set(self.hash_picker.current())
        # print("Switch hash", new_hash)

        for widget in self.file_picker.winfo_children():
            widget.destroy()

        all_dupes_for_hash = self.duplicates[self.current_hash]

        self.current_file.set("")
        self.current_filelist = list(filter(self.trash.isfile, all_dupes_for_hash))
        self.current_filelist = sorted(self.current_filelist, key=makeSortTupleAll)
        logger.debug("\n" + explainSort(self.current_filelist))

        logger.debug("Switched to hash '%s'", self.current_hash)
        # ogger.debug("Known duplicates: %s", all_dupes_for_hash)
        # logger.debug("Shown duplicates: %s", self.current_filelist)
        # self.listbox_images.delete(0, self.listbox_images.size())
        for filename in self.current_filelist:
            tk.Radiobutton(
                self.file_picker,
                text=filename,
                variable=self.current_file,
                value=filename
            ).pack(anchor="w")

            if not self.current_file.get():
                self.current_file.set(filename)

        try:
            # Only enable if there are multiple unique images in the list
            if len(set(Image.open(p).size for p in self.current_filelist)) == 1:
                self.btn_concat.config(state="normal")
            else:
                self.btn_concat.config(state="disabled")
        except Exception:
            self.btn_concat.config(state="disabled")

        try:
            next_image_hash = self.duplicate_hash_list[self.hash_picker.current() + 1]
            self.canvas.preloadImage(self.duplicates[next_image_hash])
        except IndexError:
            logger.warning("Not preloading next image (indexerror)")


if __name__ == "__main__":
    try:
        MainWindow()
        print("Done")
        os.abort()
    except Exception:
        traceback.print_exc()
        os.abort()
