import argparse
import cv2
import os.path
import glob
import dataclasses
import logging
import typing
import itertools
import re
import traceback

import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from _tkinter import TclError

from PIL import Image
from tkinter import ttk

import snip.filesystem
from snip import tkit
from snip.tkit.contentcanvas import ContentCanvas

import dupedb

from dedupc import explainSort
from dedupc import makeSortTupleAll

from dedupc import getSuperState


match_exts = [".jpg", ".gif", ".webm", ".png"]

# TODO: Button that asks for a file prefix, then renames
# all files in the list (sorted alphabetically)

# from PIL import Image
# from tkinter import messagebox
# from snip import tkit
# from PIL import ImageTk
# import tkinter.font as tkFont
# import threading
# import glob             # File globbing

logger = logging.getLogger(__name__)

Filestem = typing.NewType('Filestem', str)
Filepath = typing.NewType('Filepath', str)
Dirpath = typing.NewType('Dirpath', str)

@dataclasses.dataclass
class SeriesInfo():
    no: int
    style: str


def tkEnsaftenString(str_: str) -> str:
    """
    >>> tkEnsaftenString("waifu-💞.jpg")
    'waifu--.jpg'
    """
    return ''.join([
        (c if ord(c) in range(65536) else '-')
        for c in str_
    ])


def parse_args() -> argparse.Namespace:
    """Parse args from command line and return the namespace.
    """
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "shelvefile", help="Database name")

    ap.add_argument(
        "--threshhold", default=2, type=int, help="Min number of duplicates")
    ap.add_argument(
        "--limit", default=600, type=int, help="Max number of total files to load")
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


# TODO: Replace <#> with python native format strings

def getSeriesInfo(filestem: str) -> typing.Optional[SeriesInfo]:
    """Given a filestem, try to find semantic information about its
    position in a series and formatting for peer entries.

    >>> getSeriesInfo("image (32)")
    SeriesInfo(no=32, style='image (<#>)')

    >>> getSeriesInfo("39ab3j 02 imgur album")
    SeriesInfo(no=2, style='39ab3j <#> imgur album')
    """
    patterns = [
        # (r"_0(\d)_1$",    "_0<#>_1"),    # Patreon
        # (r"o(\d+)_1280$", "o<#>_1280"),  # Tumblr
        (r"_(\d+)$",                      "_<#>"),
        (r"-(\d+)$",                      "-<#>"),
        (r" (\d+)$",                      " <#>"),
        (r"\((\d+)\)$",                   "(<#>)"),
        (r"_p(\d+)$",                     "_p<#>"),
        (r"_img(\d+)$",                   "_img<#>"),
        (r"-img(\d+)$",                   "-img<#>"),
        (r"-alt(\d*)$",                   "-alt<#>"),
        (r" edit$",                       " edit<#>"),
        (r"-(\d+)_1_",                    "-<#>_1_"),
        (r"(?<=^[0-9a-z]{7} )([\d]{2}) ", "imgur<#>"),
        (r"(?<=[a-zA-Z])(\d)$",           "<#>"),
    ]
    for (pattern, stylem) in patterns:
        match = re.search(pattern, filestem)
        if match:
            try:
                i = int(match.groups()[0])
            except (IndexError, ValueError):
                i = 1
            if i > 1000:
                continue
            # style is a name template
            style = re.sub(pattern, stylem, filestem)
            return SeriesInfo(i, style)

    return None


def altPathOf(filepath: Filepath) -> Filepath:
    """Given a filepath, return a path to a new, alternate file
    The returned filepath will not already exist.

    """

    filestem, suffix = os.path.splitext(filepath)
    dirname = os.path.dirname(filepath)

    seriesinfo = getSeriesInfo(filestem)
    if seriesinfo:
        i: int = seriesinfo.no
        style: str = seriesinfo.style
    else:
        i = 1
        style = filestem + " (<#>)"

    # Increment style number until we find a path that is available

    checks = 0  # Limit the number of times we check isfile

    working_path = Filepath(os.path.join(
        dirname,
        f"{style.replace('<#>', str(i))}{suffix}"
    ))

    while (working_path == filepath) or os.path.exists(working_path):
        i += 1
        checks += 1
        working_path = Filepath(os.path.join(
            dirname,
            f"{style.replace('<#>', str(i))}{suffix}"
        ))

        if checks > 100:
            raise

    return working_path


def findBaseFileForPath(path: Filepath) -> typing.Optional[Filepath]:
    """Given a path, find the expected "base file" for alts, or previous in a series."""
    filestem, suffix = os.path.splitext(path)  # noqa: F841

    # Try to get series info (number, style) and check for previous
    seriesinfo = getSeriesInfo(filestem)
    if seriesinfo:
        prev_base_name = seriesinfo.style.replace("<#>", str(seriesinfo.no - 1))
        logger.info((filestem, prev_base_name, seriesinfo.style))
        if prev_base_name != filestem:
            for ext in match_exts:
                if os.path.isfile(prev_base_name + ext):
                    return Filepath(prev_base_name + ext)

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
        match = re.search(pattern, filestem)
        if match:
            glob_pattern: str = re.sub(r"([\[\]])", r"\\\g<1>", re.sub(pattern, sub, filestem))
            logger.info(f"Searching for file matching glob {glob_pattern!r}")
            g = glob.glob(glob_pattern)
            if len(g) > 1:
                return Filepath(g[0])

    return None


class MainWindow(tk.Tk):
    def __init__(self, *args_, **kwargs) -> None:
        super().__init__(*args_, **kwargs)

        try:
            args = parse_args()

            self.criteria: typing.Mapping[str, frozenset] = {
                "good_names": frozenset(args.good_names),
                "bad_names": frozenset(args.bad_names),
                "good_dirs": frozenset(args.good_dirs),
                "bad_dirs": frozenset(args.bad_dirs),
            }
            logger.debug(self.criteria)

            self.ignore_dirs: list[str] = args.ignore_dirs
            self.whitelist_dirs: list[str] = args.whitelist_dirs

            self.load_limit: int = args.limit

            self.threshhold: int = args.threshhold

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

    def pick_and_open_shelvefile(self) -> None:
        self.open_shelvefile(
            os.path.splitext(
                os.path.split(
                    filedialog.askopenfilename()
                )[-1]
            )[0]
        )

    def open_shelvefile(self, shelvefile) -> None:
        if not shelvefile:
            return

        self.db: dupedb.db = dupedb.db(shelvefile, strict_mode=False)
        self.trash: snip.filesystem.Trash = snip.filesystem.Trash(verbose=True)

        self.current_hash: str = ""

        self.current_file_sv: tk.StringVar = tk.StringVar()
        self.current_file_sv.set("")
        self.current_file_sv.trace("w", self.onFileSelect)

        self.current_filelist: list[Filepath] = []

        self.loadDuplicates()

    def destroy(self) -> None:
        self.db.applyJournal()
        self.trash.finish()
        super().destroy()

    def initwindow(self) -> None:

        self.geometry("950x800")

        self.infobox: tk.Label = tk.Label(self)
        self.infobox.grid(column=1, row=0, sticky="ew")

        self.file_picker: tk.Frame = tk.Frame(self, relief=tk.GROOVE)
        self.file_picker.grid(column=1, row=1, sticky="nsw")
        # Minimium size here to avoid some expensive canvas resizing
        self.grid_rowconfigure(1, minsize=82)

        self.canvas: ContentCanvas = ContentCanvas(self, takefocus=True)
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
        self.bind("<g>", self.on_btn_makegroup)
        self.bind("<c>", self.on_btn_concat)

        self.bind("<s>", self.on_btn_superdelete)
        self.bind("<0>", self.on_btn_superdelete)

        self.canvas.focus()

        self.toolbar: tk.Frame = tk.Frame(self)
        self.toolbar.grid(column=0, row=0, rowspan=3, sticky="ns")

        in_order_row: int = 0

        def rowInOrder() -> int:
            """Helper function to increment in-order elements"""
            nonlocal in_order_row
            in_order_row += 1
            return in_order_row

        self.hash_picker = ttk.Combobox(self.toolbar, state="readonly", takefocus=False)
        self.hash_picker.bind("<<ComboboxSelected>>", self.onHashSelect)
        self.hash_picker.grid(column=0, row=rowInOrder(), sticky="ew")

        btn_open = ttk.Button(self.toolbar, text="Open", takefocus=False, command=self.pick_and_open_shelvefile)
        btn_delete = ttk.Button(self.toolbar, text="Delete", takefocus=False, command=self.on_btn_delete)
        btn_move = ttk.Button(self.toolbar, text="Move", takefocus=False, command=self.on_btn_move)
        btn_replace = ttk.Button(self.toolbar, text="Replace", takefocus=False, command=self.on_btn_replace)
        self.btn_concat = btn_concat = ttk.Button(self.toolbar, text="Concatenate", takefocus=False, command=self.on_btn_concat)
        btn_makegroup = ttk.Button(self.toolbar, text="Make Group", takefocus=False, command=self.on_btn_makegroup)

        self.opt_hidealts_var = tk.BooleanVar(value=True)
        opt_hidealts = ttk.Checkbutton(self.toolbar, text="Hide known alts", variable=self.opt_hidealts_var)
        self.opt_hidealts_var.trace("w", lambda *a: self.loadDuplicates())  # noqa: ARG005

        self.opt_confirm_superdelete_var = tk.BooleanVar(value=False)
        opt_confirm_superdelete = ttk.Checkbutton(self.toolbar, text="Require S confirm", variable=self.opt_confirm_superdelete_var)

        self.var_progbar_seek = tk.IntVar()
        self.progbar_seek = ttk.Scale(self.toolbar, takefocus=False, variable=self.var_progbar_seek, command=self.on_adjust_seek)

        for btn in [btn_open, btn_delete, btn_move, btn_replace, btn_makegroup, btn_concat, opt_hidealts, opt_confirm_superdelete, self.progbar_seek]:
            btn.grid(row=rowInOrder(), sticky="ew")

    def on_adjust_seek(self, event) -> None:
        self.hash_picker.current(newindex=int(float(event)))
        self.onHashSelect()

    def update_infobox(self) -> None:
        self.infobox.configure(text=self.canvas.getInfoLabel())

    # Navigate

    def nextImage(self, *args):  # noqa: ARG002
        return self.modImage(1)

    def prevImage(self, *args):  # noqa: ARG002
        return self.modImage(-1)

    def modImage(self, mod: int) -> None:
        current_file: Filepath = Filepath(self.current_file_sv.get())
        if not current_file:
            logger.error("No current_file!")
            next_image_index: int = 0
        else:
            next_image_index = self.current_filelist.index(current_file) + mod

        next_image = self.current_filelist[next_image_index % len(self.current_filelist)]
        try:
            self.current_file_sv.set(next_image)
        except:
            logger.error(f"Couldn't set current file {next_image!r}")
            raise

    def nextHash(self, *args):  # noqa: ARG002
        return self.modHash(1)

    def prevHash(self, *args):  # noqa: ARG002
        return self.modHash(-1)

    def modHash(self, mod: int) -> None:
        try:
            self.hash_picker.current(newindex=self.hash_picker.current() + mod)
        except tk.TclError:
            self.bell()
        self.onHashSelect()

    # Process actions

    def currentFilelistRelative(self) -> list[Filepath]:
        current_file: Filepath = Filepath(self.current_file_sv.get())
        if not current_file:
            current_index: int = 0
        else:
            current_index = self.current_filelist.index(current_file)

        filelist: list[Filepath] = self.current_filelist
        rotated: list[Filepath] = filelist[current_index:] + filelist[:current_index]

        return rotated

    def on_btn_undo(self, event=None):  # noqa: ARG002
        undopath = self.trash.undo()
        if undopath:
            self.canvas.markCacheDirty(undopath)
        self.onHashSelect()

    def on_btn_delete(self, event=None) -> None:  # noqa: ARG002
        current_file: Filepath = Filepath(self.current_file_sv.get())
        if current_file:
            self.trash.delete(current_file)
            self.db.journal['removed'].append((self.hash_picker.get(), current_file))
            self.canvas.markCacheDirty(current_file)
            self.onHashSelect()

    def on_btn_superdelete(self, event=None) -> None:  # noqa: ARG002
        current_hash: str = self.hash_picker.get()
        filelist_strs: list[Filepath] = self.current_filelist

        superstate = getSuperState(filelist_strs, current_hash, criteria=self.criteria)
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

            if superstate.dest_path not in filelist_strs:
                self.duplicates[current_hash].append(superstate.dest_path)

            for f in filelist_strs:
                self.canvas.markCacheDirty(f)
                self.db.journal['validate'].append((self.hash_picker.get(), f))

            self.nextHash()

    def on_btn_replace(self, event=None) -> None:  # noqa: ARG002
        current_filelist_relative: list[Filepath] = self.currentFilelistRelative()
        # filelist_stems: list[str] = [p.stem for p in current_filelist_relative]
        permutations: list[Filepath] = [
            altPathOf(p) for p in current_filelist_relative
        ]
        source_target_paths: list[list[Filepath]] = [
            current_filelist_relative,
            permutations + current_filelist_relative
        ]
        results: typing.Optional[list[Filepath]] = tkit.MultiSelectDialog(
            self,
            ["Source: ", "Target: "],
            source_target_paths,
            stagger_lists=True
        ).results

        if results:
            source, target = results

            target_fixed: str = os.path.splitext(target)[0] + os.path.splitext(source)[1]

            # TODO: "Are you sure" on clobber
            snip.filesystem.moveFileToFile(source, target_fixed, clobber=False)
            logger.debug("replace '%s' --> '%s'", source, target_fixed)

            # if target_fixed != target:
            #     self.trash.delete(target)
            #     self.canvas.markCacheDirty(target)

            if target_fixed not in self.duplicates[self.current_hash]:
                self.duplicates[self.current_hash].append(target_fixed)

            self.canvas.markCacheDirty(source)
            self.canvas.markCacheDirty(target_fixed)

            for path in [source, target, target_fixed]:
                self.db.journal['validate'].append((self.hash_picker.get(), path))

            self.onHashSelect()

        self.after(20, self.canvas.focus)

    def on_btn_move(self, event=None) -> None:  # noqa: ARG002
        current_filelist_relative: list[Filepath] = self.currentFilelistRelative()
        new_directory_choices: list[Dirpath] = [Dirpath(s) for s in
            set(os.path.dirname(p) for p in current_filelist_relative).union(  # noqa: C401
                os.path.dirname(os.path.dirname(p)) for p in current_filelist_relative
            )
        ]

        default_new_directory = Dirpath(os.path.dirname(
            current_filelist_relative[min(1, len(current_filelist_relative) - 1)]
        ))

        new_directory_choices.remove(default_new_directory)
        new_directory_choices.insert(0, default_new_directory)

        # TODO: Make sure you can pass paths like this
        results: typing.Optional[list[str]] = tkit.MultiSelectDialog(
            self,
            ["Source: ", "New directory: "],
            [
                current_filelist_relative,
                new_directory_choices
            ],
            stagger_lists=False
        ).results

        if results:
            source: Filepath = Filepath(results[0])
            target: Dirpath = Dirpath(results[1])

            if not os.path.isdir(target):
                os.makedirs(target)

            new_path = Filepath(snip.filesystem.moveFileToDir(source, target, clobber=False))
            logger.debug("move '%s' --> '%s'", source, target)

            if "unknown" not in new_path:
                self.duplicates[self.current_hash].append(new_path)

            self.onHashSelect()
        self.after(20, self.canvas.focus)

    def on_btn_concat(self, event=None) -> None:  # noqa: ARG002
        current_filelist_relative: list[Filepath] = self.currentFilelistRelative()
        images = [cv2.imread(path) for path in current_filelist_relative]
        height, width, __ = images[0].shape

        concat = (cv2.vconcat(images) if width > height else cv2.hconcat(images))

        current_file_dir, current_file = os.path.split(self.current_file_sv.get())
        simple_name, __ = os.path.splitext(current_file)

        new_file_name: Filepath = Filepath(os.path.normpath(filedialog.asksaveasfilename(
            initialdir=current_file_dir,
            initialfile=f"{simple_name}_concat.jpg"
        )))

        if new_file_name == ".":
            return

        logger.debug(
            "concatinating '%s' to '%s' with method '%s'",
            current_filelist_relative,
            new_file_name,
            concat
        )

        cv2.imwrite(new_file_name, concat)
        self.duplicates[self.current_hash].append(new_file_name)
        self.onHashSelect()

    def on_btn_makegroup(self, event=None) -> None:  # noqa: ARG002
        current_filelist_relative: list[Filepath] = self.currentFilelistRelative()

        prefix_choices: list[Filestem] = [
            Filestem(os.path.splitext(p)[0])
            for p in current_filelist_relative
        ]

        prefix: typing.Optional[str] = tkit.SelectDialog(
            self,
            "File prefix: ",
            prefix_choices
        ).result

        if prefix:
            for i, source_path in enumerate(current_filelist_relative):
                target_prefix = Filestem(f"{prefix} ({i + 1})")
                target_fixed = Filepath(target_prefix + os.path.splitext(source_path)[1])
                try:
                    # print(source_path, target_fixed)
                    snip.filesystem.moveFileToFile(source_path, target_fixed, clobber=False)
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
                    continue

                if target_fixed not in self.duplicates[self.current_hash]:
                    self.duplicates[self.current_hash].append(target_fixed)
                self.canvas.markCacheDirty(source_path)
                self.canvas.markCacheDirty(target_fixed)

        self.onHashSelect()

    # Load and select
    def filterFileLists(self) -> typing.Iterator[tuple[list[str], str]]:
        generator: typing.Iterator[tuple[list[str], str]] = self.db.generateDuplicateFilelists(bundleHash=True, threshhold=self.threshhold, validate=False)
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
                if any(ig.lower() in filename.lower() for ig in self.ignore_dirs):
                    logger.debug(f"{filename} ignored due to ignore_dirs '{self.ignore_dirs}'")
                    filelist.remove(filename)

            # yield (filelist, bundled_hash)
            if self.opt_hidealts_var.get():
                base_names: set[str] = {os.path.splitext(p)[0] for p in filelist if len(os.path.split(p)[1]) > 18}

                # Add imgur album IDs as bases to match
                for plain_name in [*base_names]:
                    match: typing.Union[typing.Match[str], None] = re.match(r'(.+[\\/][0-9a-z]+ )([0-9]+) (.+)', plain_name)
                    if match:
                        base_names.add(match.group(1))

                filelist_no_series: list[str] = filelist.copy()

                for filename in map(Filepath, filelist):
                    # String slicing method
                    our_base_name: str = os.path.splitext(filename)[0]
                    other_base_names: set[str] = {
                        os.path.splitext(p)[0]
                        for p in filelist
                        if p != filename and len(os.path.split(p)[1]) > 18
                    }

                    # base_name_quick_stub = base_name_quick[:-12]
                    # base_name_len = len(base_name_quick)
                    # logger.info(repr((base_names, base_name_quick)))
                    # logger.info(base_names.difference({base_name_quick}))
                    # logger.info(base_name_quick)
                    # logger.info(base_name_quick_stub)
                    #
                    if any(our_base_name.startswith(n) for n in other_base_names):
                        logger.debug(f"{filename!r} has simple base file for '{our_base_name!r}' in {other_base_names}")
                        filelist_no_series.remove(filename)
                        if our_base_name in base_names:
                            base_names.remove(our_base_name)
                        else:
                            logger.warning(f"{our_base_name=} not in startswith {other_base_names=}")
                        continue
                    elif any(our_base_name.startswith(n[:-6]) for n in other_base_names):
                        logger.debug(f"{filename!r} has partial base match for '{our_base_name!r}' in {other_base_names}")
                        filelist_no_series.remove(filename)
                        if our_base_name in base_names:
                            base_names.remove(our_base_name)
                        else:
                            logger.warning(f"{our_base_name=} not in sliced startswith {other_base_names=}")
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

                yield (filelist, bundled_hash)

    def loadDuplicates(self) -> None:

        self.duplicates: dict[str, list[str]] = {}

        for (filelist, bundled_hash) in itertools.islice(self.filterFileLists(), self.load_limit):
            self.duplicates[bundled_hash] = filelist
            # if len(self.duplicates.keys()) > 5:
            #     break

        self.db.applyJournal()

        self.duplicate_hash_list = sorted(
            self.duplicates.keys(),
            key=lambda k: self.duplicates.get(k)[:1]  # type: ignore[index]
        )
        self.hash_picker.configure(values=self.duplicate_hash_list)
        self.hash_picker.current(0)
        self.progbar_seek.configure(to=len(self.duplicate_hash_list))
        self.onHashSelect()

    def onFileSelect(self, *args):  # noqa: ARG002
        new_file = self.current_file_sv.get()
        # logger.debug("Switch file to '%s'", new_file)
        self.canvas.setFile(new_file)
        self.update_infobox()

    def onHashSelect(self, *args) -> None:  # noqa: ARG002
        self.current_hash = self.hash_picker.get()
        self.var_progbar_seek.set(self.hash_picker.current())
        # print("Switch hash", new_hash)

        for widget in self.file_picker.winfo_children():
            widget.destroy()

        all_dupes_for_hash = self.duplicates[self.current_hash]

        self.current_file_sv.set("")
        self.current_filelist = [*map(Filepath, filter(self.trash.isfile, all_dupes_for_hash))]
        try:
            self.current_filelist = sorted(self.current_filelist)
            self.current_filelist = sorted(self.current_filelist, key=lambda x: makeSortTupleAll(x, criteria=self.criteria))
        except Exception:
            logger.error(self.current_filelist, exc_info=True)
            # raise

        try:
            logger.debug("\n" + explainSort(self.current_filelist))
        except Exception:
            logger.error("Couldn't explainSort", exc_info=True)
            return

        logger.debug("Switched to hash '%s'", self.current_hash)
        # ogger.debug("Known duplicates: %s", all_dupes_for_hash)
        # logger.debug("Shown duplicates: %s", self.current_filelist)
        # self.listbox_images.delete(0, self.listbox_images.size())

        superstate = getSuperState(self.current_filelist, self.current_hash, criteria=self.criteria)

        for filename in self.current_filelist:
            filename_label = f"{filename}*" if filename == superstate.dest_path else filename
            tk.Radiobutton(
                self.file_picker,
                text=tkEnsaftenString(filename_label),
                variable=self.current_file_sv,
                value=filename
            ).pack(anchor="w")

            if not self.current_file_sv.get():
                self.current_file_sv.set(filename)

        if superstate.dest_path not in self.current_filelist:
            tk.Label(
                self.file_picker,
                text=f">> {superstate.dest_path}*"
            ).pack(anchor="w")

        try:
            # Only enable if there are multiple unique images in the list
            if len(set(Image.open(p).size for p in self.current_filelist)) == 1:  # noqa: C401
                self.btn_concat.config(state="normal")
            else:
                self.btn_concat.config(state="disabled")
        except Exception:  # noqa: BLE001
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
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        os.abort()
