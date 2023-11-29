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

import glob

import functools
import re
from pathlib import Path

from dedupc import getSuperState

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
    ap.add_argument(
        "--whitelist_dirs", nargs='+', default=[],
        help="Substrings to require in the path to include in comparison.")
    ap.add_argument(
        "--ignore_dirs", nargs='+', default=[],
        help="Substrings in the path to exclude from comparison entirely.")
    args = ap.parse_args()
    # Workaround for https://bugs.python.org/issue9334
    args.good_names = {s.replace(r"\-", "-") for s in args.good_names}
    args.bad_names = {s.replace(r"\-", "-") for s in args.bad_names}
    return args

def getSeriesInfo(name):
    from collections import namedtuple
    patterns = [
        # (r"_0(\d)_1$",    "_0<#>_1"),    # Patreon
        # (r"o(\d+)_1280$", "o<#>_1280"),  # Tumblr
        (r"_(\d+)$",            "_<#>"),
        (r"-(\d+)$",            "-<#>"),
        (r" (\d+)$",            " <#>"),
        (r"\((\d+)\)$",         "(<#>)"),
        (r"_p(\d+)$",           "_p<#>"),
        (r"_img(\d+)$",         "_img<#>"),
        (r"-img(\d+)$",         "-img<#>"),
        (r"-alt(\d*)$",         "-alt<#>"),
        (r" edit$",             " edit<#>"),
        (r"-(\d+)_1_",          "-<#>_1_"),
        (r"(?<=[a-zA-Z])(\d)$", "<#>"),
    ]
    for (pattern, stylem) in patterns:
        match = re.search(pattern, name)
        if match:
            try:
                i = int(match.groups()[0])
            except (IndexError, ValueError):
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
        style = stem + " (<#>)"

    checks = 0  # Limit the number of times we check isfile

    working_path = os.path.join(
        dirname,
        f"{style.replace('<#>', str(i))}{ext}"
    )

    while (working_path == path) or os.path.isfile(working_path):
        i += 1
        checks += 1
        working_path = os.path.normpath(os.path.join(
            dirname,
            f"{style.replace('<#>', str(i))}{ext}"
        ))
        assert checks < 100
    return working_path

def findBaseFileForPath(path):
    name = os.path.splitext(path)[0]

    seriesinfo = getSeriesInfo(name)
    if seriesinfo:
        # Try to find previous
        i, style = seriesinfo
        prev_base_name = style.replace("<#>", str(i - 1))
        if prev_base_name != name:
            for ext in match_exts:
                if os.path.isfile(prev_base_name + ext):
                    # logger.debug(f"Found {prev_base_name}")
                    return prev_base_name
                # else:
                #     logger.debug(f"Not previous '{prev_base_name + ext}'")

    # Find common base
    patterns = [
        (r"[-_ ][\d+]$", '*'),
        (r" \([0-9]\)$", '*'),
        (r"(\\\w+\-pn_\d+_)[^\\]+$", r"\g<1>*"),
        (r" otm$", '*'),
        (r" otn$", '*'),
        (r"[-_ ]alt$", '*'),
        (r"[-_ ]edit$", '*'),
        # (r"-(\d+)_1_", "-*_1_"),
    ]
    for (pattern, sub) in patterns:
        match = re.search(pattern, name)
        if match:
            g = glob.glob(re.sub(r"([\[\]])", r"\\\g<1>", re.sub(pattern, sub, name)))
            if len(g) > 1:
                # logger.debug(f"Found {g}")
                return g[0]
        #     else:
        #         logger.debug(f"Not glob '{re.sub(pattern, sub, name)}', '{g}'")
        # else:
        #     logger.debug(f"Not pattern '{pattern}'")

    return False


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
            logger.debug(self.criteria)

            self.ignore_dirs = args.ignore_dirs
            self.whitelist_dirs = args.whitelist_dirs


            self.threshhold = args.threshhold

            self.initwindow()

            try:
                if not args.shelvefile:
                    self.pick_and_open_shelvefile()
                else:
                    self.open_shelvefile(args.shelvefile)
            except TclError as e:
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

        self.db = dupedb.db(shelvefile, strict_mode=False)
        self.trash = snip.filesystem.Trash(verbose=True)

        self.current_hash = ""

        self.current_file = tk.StringVar()
        self.current_file.set("")
        self.current_file.trace("w", self.onFileSelect)

        self.current_filelist = []

        self.loadDuplicates()

    def destroy(self):
        self.db.applyJournal()
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

        self.opt_hidealts_var = tk.BooleanVar(value=True)
        opt_hidealts = ttk.Checkbutton(self.toolbar, text="Hide known alts", variable=self.opt_hidealts_var)
        self.opt_hidealts_var.trace("w", lambda *a: self.loadDuplicates())

        self.opt_confirm_superdelete_var = tk.BooleanVar(value=False)
        opt_confirm_superdelete = ttk.Checkbutton(self.toolbar, text="Require S confirm", variable=self.opt_confirm_superdelete_var)

        self.var_progbar_seek = tk.IntVar()
        self.progbar_seek = ttk.Scale(self.toolbar, takefocus=False, variable=self.var_progbar_seek, command=self.on_adjust_seek)

        for btn in [btn_open, btn_delete, btn_move, btn_replace, btn_concat, opt_hidealts, opt_confirm_superdelete, self.progbar_seek]:
            btn.grid(row=rowInOrder(), sticky="ew")

    def on_adjust_seek(self, event):
        self.hash_picker.current(newindex=int(float(event)))
        self.onHashSelect()

    def update_infobox(self):
        # filepath = self.current_file.get()
        # if not filepath:
        #     return

        # filename = os.path.split(filepath)[1]
        # filesize = os.path.getsize(filepath)
        # filesize_str = snip.strings.bytes_to_string(filesize)
        # try:
        #     frames = snip.image.framesInImage(filepath)
        #     w, h = Image.open(filepath).size
        #     ratio = filesize / (w * h)
        #     newtext = f"{filename} [{frames}f]\n{filesize_str} [{w}x{h}px] [{ratio}]"
        # except Exception:
        #     newtext = f"{filename} \n{filesize_str}"
        #     # traceback.print_exc()
        self.infobox.configure(text=self.canvas.getInfoLabel())

    # Navigate

    def nextImage(self, *args):
        return self.modImage(1)

    def prevImage(self, *args):
        return self.modImage(-1)

    def modImage(self, mod):
        next_image_index = self.current_filelist.index(self.current_file.get()) + mod
        next_image = self.current_filelist[next_image_index % len(self.current_filelist)]
        try:
            self.current_file.set(next_image)
        except:
            logger.error(next_image)
            raise

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
        self.db.journal['removed'].append((self.hash_picker.get(), filepath))
        self.canvas.markCacheDirty(filepath)
        self.onHashSelect()

    def on_btn_superdelete(self, event=None):

        current_hash = self.hash_picker.get()
        filelist = self.current_filelist

        superstate = getSuperState(filelist, current_hash, criteria=self.criteria)
        logger.debug(superstate)

        should_do = (not self.opt_confirm_superdelete_var.get()) or messagebox.askyesno(
            title="Confirm",
            message=f"Do superdelete operation?\n{superstate.explain_string}"
        )
        if should_do is True:
            for path in superstate.deletions:
                self.trash.delete(path, rename=True)

            if superstate.needs_move:
                snip.filesystem.moveFileToFile(
                    superstate.best_image,
                    superstate.dest_path,
                    clobber=False
                )

            if superstate.dest_path not in filelist:
                self.duplicates[current_hash].append(superstate.dest_path)

            for f in filelist:
                self.canvas.markCacheDirty(f)
                self.db.journal['validate'].append((self.hash_picker.get(), f))
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

            # TODO: "Are you sure" on clobber
            snip.filesystem.moveFileToFile(source, target_fixed, clobber=False)
            logger.debug("replace '%s' --> '%s'", source, target_fixed)

            if target_fixed != target:
                self.trash.delete(target)
                self.canvas.markCacheDirty(target)

            if target_fixed not in self.duplicates[self.current_hash]:
                self.duplicates[self.current_hash].append(target_fixed)
            self.canvas.markCacheDirty(source)
            self.canvas.markCacheDirty(target_fixed)

            for path in [source, target, target_fixed]:
                self.db.journal['validate'].append((self.hash_picker.get(), path))

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

            if "unknown" not in new_path:
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

        generator = self.db.generateDuplicateFilelists(bundleHash=True, threshhold=self.threshhold, validate=False)
        self.duplicates = {}
        for (filelist, bundled_hash) in generator:
            if int(bundled_hash, base=16) == 0:
                print(f"bundled_hash '{bundled_hash}' is a zero hash.")
                continue
            if self.whitelist_dirs:
                white_ok = False
                for white_dir in self.whitelist_dirs:
                    if any(white_dir.lower() in os.path.split(filename)[0].lower() for filename in filelist):
                        white_ok = True
                        break
                if not white_ok:
                    continue
            for filename in filelist.copy():
                if any(ig.lower() in os.path.split(filename)[0].lower() for ig in self.ignore_dirs):
                    logger.debug(f"{filename} ignored due to '{self.ignore_dirs}'")
                    filelist.remove(filename)

            if self.opt_hidealts_var.get():
                base_names = {os.path.splitext(p)[0] for p in filelist if len(os.path.split(p)[1]) > 18}

                # Add imgur album IDs as bases to match
                for plain_name in [*base_names]:
                    match = re.match(r'(.+[\\/][0-9a-z]+ )([0-9]+) (.+)', plain_name)
                    if match:
                        base_names.add(match.group(1))

                filelist_no_series = filelist.copy()

                for filename in filelist:
                    # String slicing method
                    our_base_name = os.path.splitext(filename)[0]
                    other_base_names = base_names.difference({our_base_name})

                    # base_name_quick_stub = base_name_quick[:-12]
                    # base_name_len = len(base_name_quick)
                    # logger.info(repr((base_names, base_name_quick)))
                    # logger.info(base_names.difference({base_name_quick}))
                    # logger.info(base_name_quick)
                    # logger.info(base_name_quick_stub)
                    #
                    if any(our_base_name.startswith(n) for n in other_base_names):
                        logger.debug(f"{filename} has simple base file for '{our_base_name}' in {other_base_names}")
                        filelist_no_series.remove(filename)
                        if our_base_name in base_names:
                            base_names.remove(our_base_name)
                        else:
                            logger.warning(f"{our_base_name} not in {other_base_names}")
                        continue
                    elif any(our_base_name.startswith(n[:-6]) for n in other_base_names):
                        logger.debug(f"{filename} has partial base match for '{our_base_name}' in {other_base_names}")
                        filelist_no_series.remove(filename)
                        if our_base_name in base_names:
                            base_names.remove(our_base_name)
                        else:
                            logger.warning(f"{our_base_name} not in {other_base_names}")
                        continue
                    else:
                        logger.debug(f"{our_base_name} has no base file for in {other_base_names}")

                    # Smart method
                    base_name = findBaseFileForPath(filename)
                    if base_name in filelist_no_series:
                        logger.debug(f"{filename} has base file in {base_name}")
                        filelist_no_series.remove(filename)
                        continue

                if len(filelist_no_series) < self.threshhold:
                    continue

                # Validate *now*, with reduced list:
                for filepath in filelist_no_series.copy():
                    if not self.db.validateHash(bundled_hash, filepath):
                        filelist_no_series.remove(filepath)
                        self.db.journal["removed"].append((bundled_hash, filepath))

                if len(filelist_no_series) < self.threshhold:
                    continue

            self.duplicates[bundled_hash] = filelist
            # if len(self.duplicates.keys()) > 5:
            #     break
        self.db.applyJournal()

        self.duplicate_hash_list = sorted(
            list(self.duplicates.keys()),
            key=lambda k: self.duplicates.get(k)[:1]
        )
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

        superstate = getSuperState(self.current_filelist, self.current_hash, criteria=self.criteria)

        for filename in self.current_filelist:
            filename_label = f"{filename}*" if filename == superstate.dest_path else filename
            tk.Radiobutton(
                self.file_picker,
                text=filename_label,
                variable=self.current_file,
                value=filename
            ).pack(anchor="w")

            if not self.current_file.get():
                self.current_file.set(filename)
        if superstate.dest_path not in self.current_filelist:
            tk.Label(
                self.file_picker,
                text=f">> {superstate.dest_path}*"
            ).pack(anchor="w")

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
