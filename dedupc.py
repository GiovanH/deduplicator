import argparse         # Argument parsing
import subprocess       # Magick runner
import glob             # File globbing
from time import time   # Time IDs
import os.path          # isfile() method
import re

import snip

import traceback
from PIL import Image
import snip.filesystem
import dupedb
from functools import lru_cache
from collections import namedtuple
import tqdm
import itertools
import json

from snip.stream import TriadLogger
# logger = TriadLogger(__name__)

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# SHELVE_FILE_EXTENSIONS = ["json"]
EMPTY_SET: set = frozenset()


def deleteFiles(filestodelete: list[str]) -> None:
    """Trash multiple files

    Args:
        filestodelete (list): File paths to delete
    """
    with snip.filesystem.Trash() as trash:
        for path in filestodelete:
            trash.delete(path)


def imageSize(filename: str) -> int:
    """
    Args:
        filename (str): Path to an image on disk

    Returns:
        int: Pixels in image or 0 if file is not an image.

    Raises:
        FileNotFoundError: Path is not on disk
    """

    try:
        w, h = Image.open(filename).size
        size = w * h
        return size
    except Image.DecompressionBombError:
        return Image.MAX_IMAGE_PIXELS
    except FileNotFoundError:
        logger.error("File not found: " + filename)
        raise FileNotFoundError(filename)
    except OSError:
        # print("WARNING! OS error with file: " + filename)
        # traceback.print_exc()
        return 1


def makeImageSortTuple(x: str) -> tuple[int, float]:
    getsize: int = os.path.getsize(x)
    image_size: int = imageSize(x)
    return (
        -snip.image.framesInImage(x),  # High frames good
        -image_size,  # High resolution good
        -getsize,  # High filesize good (if resolution is the same!)
        -(getsize / image_size),  # Density
    )

@lru_cache()
def makeDirSortTuple(x: str, good_words=EMPTY_SET, bad_words=EMPTY_SET) -> tuple[int, float]:
    dirs = os.path.split(x)[0].lower()
    return (
        -sum([dirs.count(w.lower()) for w in good_words]),  # Put images with good words higher
        +sum([dirs.count(w.lower()) for w in bad_words]),  # Put images with bad words lower
        -len(x[:x.rfind(os.path.sep)]),  # Deep paths good
    )

@lru_cache()
def makeNameSortTuple(x: str, good_words=EMPTY_SET, bad_words=EMPTY_SET) -> tuple[int, float]:
    name = os.path.split(x)[1].lower()
    return (
        +int(bool(re.match(r"^[0-9a-f]{36}\.", name))),  # we do NOT like it when it's a hash
        +int(bool(re.match(r"^\d{3}_[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12}\.", name))),  # we do NOT like it when it's a ???
        -sum([name.count(w.lower()) for w in good_words]),  # Put images with good words higher
        +sum([name.count(w.lower()) for w in bad_words]),  # Put images with bad words lower
        -sum([name.count(w.lower()) for w in "-_ +"]),  # Detailed filenames better
        +int(bool(re.search(r" \(\d+\)\.", name))),  # Don't like series (base is better)
    )


def makeSortTupleAll(x: str, criteria={}):
    return (
        makeImageSortTuple(x),
        makeDirSortTuple(x, good_words=criteria.get("good_dirs", EMPTY_SET), bad_words=criteria.get("bad_dirs", EMPTY_SET)),
        makeNameSortTuple(x, good_words=criteria.get("good_names", EMPTY_SET), bad_words=criteria.get("bad_names", EMPTY_SET)),
    )


def explainSort(paths: str, criteria={}) -> str:
    explanation = "image(-frames, -res, -size, -density), path(-good, +bad, -depth), name(-hash, -???, -good, +bad, -punctuation, +number, )"
    for path in paths:
        explanation += "\n{}\t| {} ".format(
            makeSortTupleAll(path, criteria),
            path
        )
    return explanation


def runMagickCommand(shelvefile, precmd, midcmd, fileact, sortedFilenames, bundled_hash):
    """Summary

    Args:
        shelvefile (TYPE): Description
        precmd (TYPE): Description
        midcmd (TYPE): Description
        fileact (TYPE): Description
        sortedFilenames (TYPE): Description
        bundled_hash (TYPE): Description

    Raises:
        subprocess.CalledProcessError: Description
    """
    outfile = "./comparison/{}/{}_{}.jpg".format(shelvefile, bundled_hash, fileact)

    if os.path.exists(outfile):
        # print("skip", bundled_hash)
        # return

        montageFileSize = sum(dupedb.imageSize(p) for p in sortedFilenames)
        existSize = dupedb.imageSize(outfile)
        if montageFileSize == existSize:
            # logger.warn("Path", outfile, "already exists, size matches, skipping.", montageFileSize)
            return
        else:
            logger.warn("Overwriting comparison file", outfile, existSize, "px vs", montageFileSize)

    command = ["magick"]
    command += precmd.split(" ")
    command += sortedFilenames
    if midcmd != "" and midcmd is not None:
        command += midcmd.split(" ")
    command.append(outfile)

    logger.info(outfile)

    result = subprocess.run(command, capture_output=True, check=False)
    if len(result.stderr) + len(result.stdout) > 0:
        logger.error(*((c if c.count(" ") == 0 else '"{}"'.format(c)) for c in command))
        # print("OUT:", bytes(result.stdout).decode("unicode_escape"))
        try:
            logger.error(bytes(result.stderr).decode("unicode_escape"), exc_info=True)
        except UnicodeDecodeError:
            logger.error(result.stderr, exc_info=True)
        # raise subprocess.CalledProcessError(result.returncode, command, result).


def getDuplicatesToDelete(db, criteria, interactive=False) -> list[str]:
    """Given a database, generate a list of duplicate files to delete.

    Args:
        interactive (bool, optional): Require user confirmation

    Returns:
        list: List of file paths of images marked for deletion

    Raises:
        AssertionError: Internal error, abort
    """
    # Initialize a list of file paths to delete at the end.
    filestodelete = []

    # CHECK: Process and evalulate duplicate fingerprints.
    logger.info("Checking database for duplicates")
    i = 0
    for (filelist, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=2):
        if int(bundled_hash, base=16) == 0:
            print(f"bundled_hash '{bundled_hash}' is a zero hash.")
            continue

        filelist = sorted(filelist, key=lambda x: makeImageSortTuple(x, criteria))
        if interactive:
            # The user gets to pick the image to keep.
            # Print up a pretty menu.
            print()
            for i in range(0, len(filelist)):
                print("{0}. {1}".format(i, filelist[i]))
            # Loop over the menu until the user selects a valid option
            good_ans = False
            while not good_ans:
                # Show the choices
                ans = input(
                    "\nEnter the number of the file to KEEP: (0) ('s' to skip) ")
                try:
                    if ans.upper() == "S":
                        # Skip this image (don't delete anything)
                        # and also, for good measure, output the delete file.
                        good_ans = True
                        goingtokeep = "All."
                        goingtodelete = []
                        continue
                    if ans == "":
                        ans = 0

                    index = int(ans)
                    goingtokeep = filelist[index]
                    goingtodelete = filelist[:index] + \
                        filelist[(index + 1):]
                    good_ans = True
                except ValueError:
                    print("Not a valid number. ")  # Have another go.
        else:
            # Not interactive.
            # We keep the FIRST file in the sort.
            # We'll delete the rest.
            goingtokeep = filelist[0]
            goingtodelete = filelist[1:]
            if (goingtokeep is None or len(goingtokeep) == 0):
                # Just in case.
                for sym in [filelist, goingtokeep, goingtodelete]:
                    print(sym)
                raise AssertionError("Internal logic consistancy error. Program instructed to consider ALL images with a given hash as extraneous. Please debug.")

        # However the method, add all our doomed files to the list and print our explanation.
        explanation = "\n\t" + "\n\t".join(["+ " + goingtokeep] + ["- " + f for f in goingtodelete])
        logger.info(explanation)

        filestodelete += goingtodelete

    return filestodelete


def listDuplicates(db):
    for (filepaths, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=2):
        # print(f"Got {filepaths!r}, {bundled_hash}")

        filepaths = sorted(filepaths, key=makeImageSortTuple)
        print(bundled_hash)
        lfilepaths = len(filepaths)
        tags = [" └─ " if i == lfilepaths - 1 else " ├─ " for i in range(0, lfilepaths)]
        for i, filepath in enumerate(filepaths):
            print(tags[i] + filepath)
        print("\n")


def processRenameOperation(old_path, new_name, bundled_hash, successful_operations, mock=False, clobber=False):
    """Appropriately renames files. 
    Designed to run in a thread. 
    Successful operations accumulate in list successful_operations

    Args:
        old_path (TYPE): Description
        new_name (TYPE): Description
        bundled_hash (str): Perceptual hash of image at file

    Deleted Parameters:
        old (str): Old file path
        new (str): New file path

    Returns:
        TYPE: Description
    """

    old_dir, old_name = os.path.split(old_path)
    new_path = os.path.join(old_dir, new_name)

    if mock:
        logger.warn("MOCK: {} -X-> {}".format(old_path, new_path))
        return

    try:
        snip.filesystem.moveFileToFile(old_path, new_path, clobber=False)
    except FileExistsError:
        # Implement our own clobber behavior
        if clobber:
            # Trash existing, then replace.
            with snip.filesystem.Trash() as trash:
                trash.delete(new_path)
            snip.filesystem.moveFileToFile(old_path, new_path, clobber=False)
    successful_operations.append((old_path, new_path, bundled_hash,))


def _doSuperDelete(filepaths, bundled_hash, delete, criteria={}, mock=True, explain=logger.info, no_debug=False) -> str:
    image_rating = {f: makeImageSortTuple(f) for f in filepaths}
    sorted_by_best_image = sorted(filepaths, key=image_rating.get)

    # Determine best image, dir, name
    best_image = sorted_by_best_image[0]
    best_dir = sorted(filepaths, key=lambda x: makeDirSortTuple(x, criteria.get("good_dirs", EMPTY_SET), criteria.get("bad_dirs", EMPTY_SET)))[0]
    best_name = sorted(filepaths, key=lambda x: makeNameSortTuple(x, criteria.get("good_names", EMPTY_SET), criteria.get("bad_names", EMPTY_SET)))[0]

    if not no_debug:
        logger.debug(explainSort(filepaths, criteria))
        logger.debug("Best image: '%s'", best_image)
        logger.debug("Best dir:   '%s'", os.path.split(best_dir)[0])
        logger.debug("Best name:  '%s'", os.path.split(best_name)[1])

    files_to_delete = sorted_by_best_image[1:]
    assert best_image not in files_to_delete

    # Construct best path
    best_path = os.path.join(os.path.split(best_dir)[0], os.path.split(best_name)[1])

    if not no_debug:
        logger.debug("Best path:  '%s'", best_path)

    best_path_fix = os.path.splitext(best_path)[0] + os.path.splitext(best_image)[1]
    if best_path_fix not in filepaths:
        i = 0
        o = best_path_fix
        while os.path.isfile(best_path_fix):
            logger.warn("Path '%s' exists as another hash?", best_path_fix)
            i += 1
            best_path_fix = os.path.splitext(o)[0] + f"_{i}" + os.path.splitext(o)[1]

    # Logic

    explanation = ""

    # If the best path alreaady has "a" best image, we don't need to move
    if best_path_fix in filepaths and image_rating.get(best_path_fix) == image_rating.get(best_image):
        logger.debug("Best path '%s' is already a best image", best_path)
        files_to_delete.append(best_image)
        best_image = best_path_fix
        if best_image in files_to_delete:
            # Can happen,
            files_to_delete.remove(best_image)

    # If the best image isn't at the best path, move
    if best_image != best_path_fix:
        # logger.debug("Should move file '%s'", best_image)
        # logger.debug("              to '%s'", best_path_fix)
        explanation += "\n\t" + "> " + best_path_fix + "\n\t" + "^ " + best_image
        if best_path_fix in files_to_delete:
            logger.debug("Moving to deletion target '%s'! Must not trash!", best_path_fix)
            files_to_delete.remove(best_path_fix)
        if not mock:
            snip.filesystem.moveFileToFile(best_image, best_path_fix, clobber=True, quiet=False)
    else:
        # Otherwise, keep
        explanation += "\n\t" + "+ " + best_image

    # Log deletions
    if files_to_delete:
        # logger.debug("Should delete files '%s'", files_to_delete)
        explanation += "\n\t" + "\n\t".join(["- " + f for f in files_to_delete])
        if not mock:
            for path in files_to_delete:
                delete(path)

    # Log full explanation
    explain(explanation)
    return best_path_fix

SuperState = namedtuple("SuperState", ["best_image", "dest_path", "deletions", "needs_move", "explain_sort", "explain_string"])

def getSuperState(filepaths, bundled_hash, criteria={}) -> SuperState:
    image_rating = {f: makeImageSortTuple(f) for f in filepaths}
    dir_rating = {f: makeDirSortTuple(f, criteria.get("good_dirs", EMPTY_SET), criteria.get("bad_dirs", EMPTY_SET)) for f in filepaths}
    name_rating = {f: makeNameSortTuple(f, criteria.get("good_names", EMPTY_SET), criteria.get("bad_names", EMPTY_SET)) for f in filepaths}
    sorted_by_best_image = sorted(filepaths, key=image_rating.get)

    # Determine best image, dir, name
    try:
        best_image = sorted_by_best_image[0]
        best_dir = sorted(dir_rating, key=dir_rating.__getitem__)[0]
        best_name = sorted(name_rating, key=name_rating.__getitem__)[0]
        logger.debug(explainSort(filepaths, criteria))
        logger.debug("Best image: '%s'", best_image)
        logger.debug("Best dir:   '%s'", os.path.split(best_dir)[0])
        logger.debug("Best name:  '%s'", os.path.split(best_name)[1])
    except IndexError:
        # List too small
        return SuperState(
            best_image=None,
            dest_path=None,
            deletions=[],
            needs_move=False,
            explain_sort=None,
            explain_string="there aren't any"
        )

    files_to_delete = sorted_by_best_image[1:]
    assert best_image not in files_to_delete

    # If the name of the best image ties with the best name, use its name instead
    # logger.info("Name tying debug")
    # logger.info(f"{os.path.split(best_image)[1]=} {os.path.split(best_name)[1]=}")
    # logger.info(f"{name_rating.get(best_image)=} {name_rating.get(best_name)=}")
    if os.path.split(best_image)[1] != os.path.split(best_name)[1] and name_rating.get(best_image) == name_rating.get(best_name):
        best_name = best_image
        logger.debug("Overriding tiebreaker name: '%s'", best_name)

    # If the dir of the best image ties with the best dir, use its dir instead
    if os.path.split(best_image)[0] != os.path.split(best_dir)[0] and dir_rating.get(best_image) == dir_rating.get(best_dir):
        best_dir = best_image
        logger.debug("Overriding tiebreaker dir:  '%s'", best_dir)

    # Construct best path
    best_path = os.path.join(os.path.split(best_dir)[0], os.path.split(best_name)[1])
    logger.debug("Best path:  '%s'", best_path)

    best_path_fix = os.path.splitext(best_path)[0] + os.path.splitext(best_image)[1]
    if best_path_fix not in filepaths:
        # Make a new path
        i = 0
        o = best_path_fix
        while os.path.isfile(best_path_fix):
            logger.warn("Path '%s' exists as another hash?", best_path_fix)
            i += 1
            best_path_fix = os.path.splitext(o)[0] + f"_{i}" + os.path.splitext(o)[1]

    # Logic
    explanation = ""

    # If the name of the best 

    # If the best path alreaady has "a" best image, we don't need to move
    if best_path_fix in filepaths and image_rating.get(best_path_fix) == image_rating.get(best_image):
        explanation += f"Best path '{best_path}' is already tied for best\n"
        logger.debug(f"Best path '{best_path}' is already tied for best")

        # Delete old best image
        files_to_delete.append(best_image)

        # Keep new best image
        best_image = best_path_fix
        if best_path_fix in files_to_delete:
            files_to_delete.remove(best_path_fix)

    if files_to_delete:
        explanation += "\n" + "\n".join(["- " + f for f in files_to_delete])

    # If the best image isn't at the best path, move
    if best_image != best_path_fix:
        explanation += "\n" + "> " + best_path_fix + "\n" + "^ " + best_image
    else:
        # Otherwise, keep
        explanation += "\n" + "+ " + best_image

    # Log deletions

    return SuperState(
        best_image=best_image,
        dest_path=best_path_fix,
        deletions=files_to_delete,
        needs_move=(best_image != best_path_fix),
        explain_sort=explainSort(filepaths, criteria),
        explain_string=explanation
    )

def superdelete(db, mock, criteria) -> None:
    with snip.filesystem.Trash() as trash:
        # with snip.loom.Spool(4, name="Superdelete") as spool:
            print("Scanning for superdelete")
            for (filepaths, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=2, validate=True):
                # spool.enqueue(
                #     _doSuperDelete,
                #     (filepaths, bundled_hash, trash.delete, criteria, mock),
                #     dict(no_debug=True)
                # )
                # pass
                try:
                    _doSuperDelete(filepaths, bundled_hash, trash.delete, criteria, mock, no_debug=True)
                except OSError:
                    logger.error("Couldn't finish delete for hash '%s'", bundled_hash, exc_info=True)

@lru_cache()
def stringsAlmostEqual(s1, s2, threshhold=1):
    misses = 0

    for c1, c2 in zip(s1, s2):
        if c1 != c2:
            misses += 1
            if misses >= threshhold:
                return False
    return True

# def check_similar(db):
#     whole_db = db.getRawCopy()
#     similar_hashes = set()

#     all_keys = frozenset(whole_db.keys())

#     def _checkkey(f1):
#         for f2 in all_keys:
#             if f1 != f2 and stringsAlmostEqual(f1, f2, 2):
#                 # logger.info(f"Similar hashes: '{f1}', '{f2}'")
#                 similar_hashes.add(frozenset([f1, f2]))

#     with snip.loom.Spool(32, name="Checking") as spool:
#         for k in tqdm.tqdm(iterable=all_keys, desc="Permutating"):
#             spool.enqueue(_checkkey, (k,))

#     for f1, f2 in similar_hashes:
#         whole_db.pop(f1)
#         whole_db.pop(f2)
#     #     message = f"Similar hashes: '{f1}', '{f2}'\n"
#     #     for hash in [f2, f2]:
#     #         for filepath in db[hash]:
#     #             message += f"{hash}: {filepath}\n"
#     #     logger.info(message)

#     with open("temp.json", "w") as fp:
#         json.dump(whole_db, fp)

def parse_args():
    """
    Parse args from command line and return the namespace

    Returns:
        TYPE: Description
    """
    DEFAULT_HASH_SIZE = 12
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "-f", "--scanfiles", nargs='+',
        help="File globs that select which files to check. Globstar supported.")
    ap.add_argument(
        "--files-exempt", nargs='+', required=False, default=list(),
        help="File substrings to ignore")
    ap.add_argument(
        "-s", "--shelve",
        required=True, help="Database name")
    ap.add_argument(
        "--hashsize",
        type=int, default=DEFAULT_HASH_SIZE, help="How similar the images need to be to match. Default {}. Minimum 2. (2x2 image)".format(DEFAULT_HASH_SIZE))

    ap.add_argument(
        "--recheck", action="store_true",
        help="Re-fingerprint all files, even if they might not have changed.")

    ap.add_argument(
        "-m", "--mock", action="store_true",
        help="Don't actually delete or rename files, just print a log of which ones would be deleted.")
    ap.add_argument(
        "-i", "--interactive", action="store_true",
        help="Prompt for user selection in choosing the file to keep instead of relying on the sort algorithm.")
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
        "--clobber",
        help="Allow overwriting files during rename.", action="store_true")

    ap.add_argument(
        "-l", "--list", action="store_true",
        help="Show duplicate information on screen.")
    # ap.add_argument(
    #     "--listsimilar", action="store_true",
    #     help="Finds similar hashes in database")
    # ap.add_argument(
    #     "-r", "--renameDb", action="store_true",
    #     help="Rename files to their perceptual hash, ordering them by similarity. Renames all images in DB.")
    # ap.add_argument(
    #     "--renameFromPaths", action="store_true",
    #     help="Rename files to their perceptual hash, ordering them by similarity. Only use images passed directly, not the database.")
    ap.add_argument(
        "-d", "--delete", action="store_true",
        help="Delete duplicate files.")
    ap.add_argument(
        "--superdelete", action="store_true",
        help="Delete duplicate files but move the best files to the best paths.")

    ap.add_argument(
        "--noprogress", action="store_true",
        help="Disallow progress bars.")
    ap.add_argument(
        "--strict", action="store_true",
        help="Base hash on the entire body of images and animations")
    ap.add_argument(
        "--purge", action="store_true",
        help="Delete records of files not currently seen, even if they're in the database.")
    ap.add_argument(
        "--prune", action="store_true",
        help="Remove stale records from database in advance.")
    # ap.add_argument("--nocheck", help="Don't search the database for duplicates, just fingerprint the files in --dataset.",
    #                 action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    criteria = {
        "good_names": frozenset(args.good_names),
        "bad_names": frozenset(args.bad_names),
        "good_dirs": frozenset(args.good_dirs),
        "bad_dirs": frozenset(args.bad_dirs),
    }

    shelvefile = "{0}.s{1}".format(args.shelve, args.hashsize)

    db = dupedb.db(shelvefile, hashsize=args.hashsize, strict_mode=args.strict)

    # if args.listsimilar:
    #     check_similar(db)

    # Prune first
    if args.prune:
        db.prune()

    # Scan directories for files and populate database
    if args.scanfiles:
        logger.info("Scanning for files")
        # print(args.files)
        _image_paths = itertools.chain(*[glob.glob(a, recursive=True) for a in args.scanfiles])

        # for k in _image_paths:
        #     print(k, *((j, k.find(j) == -1,) for j in args.files_exempt))

        image_paths = [
            os.path.normpath(path) for path in
            _image_paths
            if all(path.find(j) == -1 for j in args.files_exempt)
        ]

        # File handling and fallbacks

        if args.purge:
            logger.info("Purging extra files from db")
            db.purge(keeppaths=image_paths)

        logger.info("Fingerprinting")
        db.scanDirs(image_paths, recheck=args.recheck)


    # Run commands as requested
    # if args.renameDb:
    #     renameFilesFromDb(db, mock=args.mock, clobber=args.clobber)

    # if args.renameFromPaths:
    #     renameFilesFromPaths(image_paths, args.hashsize, mock=args.mock, clobber=args.clobber)

    if args.superdelete:
        superdelete(db, mock=args.mock, criteria=criteria)

    if args.delete:
        files_to_delete = getDuplicatesToDelete(db, criteria=criteria, interactive=args.interactive)
        if not args.mock:
            deleteFiles(files_to_delete)

    if args.list:
        listDuplicates(db)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        traceback.print_exc()
        raise
