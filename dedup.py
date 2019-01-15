import loom             # Simple threading wrapper
import imagehash        # Perceptual image hashing
import argparse         # Argument parsing
import glob             # File globbing
import progressbar      # Progress bars
import os.path          # isfile() method
import traceback
import subprocess       # Magick runner
import shutil           # Moving, renaming.

from time import time   # Time IDs
from PIL import Image   # Image IO libraries
from binascii import crc32
from send2trash import send2trash
from os import sep
import hashlib

# import shelve           # Persistant data storage
import jfileutil as ju

# Todo: Replace some sep formatting with os.path.join

# Should we output debugging text about image hashes?
HASHDEBUG = False
# Should we output debugging text about sorting criteria?
SORTDEBUG = False

GLOBAL_QUIET_DEFAULT = True

DEBUG_FILE_EXISTS = False

PROGRESSBAR_ALLOWED = True

BAD_WORDS = []
fsizecache = {}
 
hasher = hashlib.md5()


def md5(path):
    with open(path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


def CRC32(filename):
    buf = open(filename, 'rb').read()
    buf = (crc32(buf) & 0xFFFFFFFF)
    return buf
#     return "%08X" % buf


def imageSize(filename):
    # Get a sortable integer representing the number of pixels in an image.
    # assert os.path.isfile(filename), filename
    h4sh = md5(filename)
    hit = fsizecache.get(h4sh)
    if hit:
        return hit

    try:
        w, h = Image.open(filename).size
        size = w * h
        fsizecache[h4sh] = size
        return size
    except FileNotFoundError:
        print("WARNING! File not found: ", filename)
        raise AssertionError(filename)
        return 0
    except OSError:
        print("WARNING! OS error with file: ", filename)
        return 0


def sortDuplicatePaths(filenames):
    """
    Takes a list of files known to be duplicates
    and sorts them in order of "desirability"
    """

    if len(filenames) <= 1:
        return filenames

    # Sorting key
    def sort(x):
        # Define our sort criteria.
        upper = x.upper()
        xtuple = (
            -imageSize(x),  # Put full resolution images higher
            -upper.count("F:{s}".format(s=sep)),  # Put images in drive F higher.
            sum([upper.count(x.upper()) for x in BAD_WORDS]),  # Put images with bad words lower
            # Put images in an exports folder lower
            upper.count("{s}EXPORTS{s}".format(s=sep)),
            # Put images with short folder paths higher
            len(x[:x.rfind(sep)]),
            upper.rfind("{s}IPAD{s}".format(s=sep)),  # Put images with iPad in the path lower
            len(x)  # Put images with short total paths higher
        )
        if SORTDEBUG:
            print(xtuple, x)
        return xtuple

    st = sorted(filenames, key=sort)
    return st


def prune(shelvefile, verbose=False, show_pbar=True):
    print("Removing dead hashes")
    empties = []
    
    with ju.Handler(shelvefile, basepath="databases", allow_writeback=True) as db:
    # with shelve.open(, writeback=False) as db:
        for key in db.keys():
            if db.get(key) == []:
                empties.append(key)

        pbar = progressbar.ProgressBar(max_value=len(empties), redirect_stdout=True) if show_pbar else None
        i = 0
        for key in empties:
            db.pop(key)
            if pbar:
                i += 1
                pbar.update(i)
            if verbose:
                print("Cleared key:", key)
        if pbar:
            pbar.finish

        ju.save(db, "databases/" + shelvefile)


def scanDirs(shelvefile, imagePaths, recheck=False, hash_size=16):
    # Resolve glob to image paths

    # Make a list of image paths we already know about. We use this to skip images
    # that probably haven't changed.
    # If we're rechecking, we don't need to build this list at all!
    if not recheck:
        with ju.Handler(shelvefile, default=dict(), basepath="databases", allow_writeback=False) as db:
            knownPaths = set([item for sublist in db.values()
                              for item in sublist])

    # prune(shelvefile)
    # not yet implemented

    # SCAN: Scan filesystem for images and hash them.

    print("Fingerprinting images with hash size {}".format(hash_size))
    with ju.Handler(shelvefile, default=dict(), basepath="databases", allow_writeback=True) as db:
        # Show a pretty progress bar
        for i in progressbar.progressbar(range(len(imagePaths))):
            imagePath = imagePaths[i]
            # If we don't know the image, or if we're doing a full recheck
            if imagePath in knownPaths and not recheck:
                continue
            # load the image and compute the difference hash
            try:
                image = Image.open(imagePath)
                h = str(imagehash.dhash(image, hash_size=hash_size))

                # extract the filename from the path and update the database
                # using the hash as the key and the filename append to the
                # list of values
                filename = imagePath  # [imagePath.rfind("/") + 1:]
                if HASHDEBUG:
                    print("File", imagePath, "has hash", h)

                # Add the path to the database if it's not already present.
                # Each Key (a hash) has a List value.
                # The list is a list of file paths with that hash.
                if filename not in db.get(h, []):
                    db[h] = db.get(h, []) + [filename]
            except FileNotFoundError:
                # print("WARNING! File not found: ", imagePath)
                # traceback.print_exc()
                pass
            except ValueError:
                print("WARNING! Error parsing image: ", imagePath)
                traceback.print_exc()
            except OSError:
                # print("File", imagePath, "is not an image file.")
                # Let's not clutter stderr with warnings about user globs
                # including non-image files.
                pass


def getDuplicatesToDelete(shelvefile, interactive=False):
    # Initialize a list of file paths to delete at the end.
    filestodelete = []
    # CHECK: Process and evalulate duplicate fingerprints.
    print("Checking database for duplicates")
    i = 0
    for filenames in generateDuplicateFilelists(shelvefile, threshhold=2):
        # filenames = sortDuplicatePaths(filenames)
        if interactive:
            # The user gets to pick the image to keep.
            # Print up a pretty menu.
            print()
            for i in range(0, len(filenames)):
                print("{0}. {1}".format(i, filenames[i]))
            # Loop over the menu until the user selects a valid option
            goodAns = False
            while not goodAns:
                # Show the choices
                ans = input(
                    "\nEnter the number of the file to KEEP: (0) ('s' to skip) ")
                try:
                    if ans.upper() == "S":
                        # Skip this image (don't delete anything)
                        # and also, for good measure, output the delete file.
                        goodAns = True
                        goingtokeep = "All."
                        goingtodelete = []
                        continue
                    if ans is "":
                        ans = 0

                    index = int(ans)
                    goingtokeep = filenames[index]
                    goingtodelete = filenames[:index] + \
                        filenames[(index + 1):]
                    goodAns = True
                except ValueError:
                    print("Not a valid number. ")  # Have another go.
        else:  # Not interactive.
            # We keep the FIRST file in the sort.
            # We'll delete the rest.
            goingtokeep = filenames[0]
            goingtodelete = filenames[1:]
            if (goingtokeep is None or len(goingtokeep) == 0):
                # Just in case.
                for sym in [filenames, goingtokeep, goingtodelete]:
                    print(sym)
                raise AssertionError("Internal logic consistancy error. Program instructed to consider ALL images with a given hash as extraneous. Please debug.")
        # However the method, add all our doomed files to the list.
        filestodelete += goingtodelete

        # And explain ourselves.
        print("\n\t* " + goingtokeep)
        print(
            "\n".join(["\t  " + f for f in goingtodelete]))
    return filestodelete


def generateDuplicateFilelists(shelvefile, bundleHash=False, threshhold=1, quiet=GLOBAL_QUIET_DEFAULT, sort=True):
    """Generate lists of files which all have the same hash."""
    print("Querying database for duplicate pictures.")
    with ju.Handler(shelvefile, basepath="databases", allow_writeback=False) as db:

        global fsizecache
        fsizecache = ju.load("sizes", default=dict())

        pbar = None
        if PROGRESSBAR_ALLOWED:
            pbar = progressbar.ProgressBar(max_value=len(db.keys()), redirect_stdout=True)
            i = 0

        for h in db.keys():
            if pbar:
                i += 1
                pbar.update(i)

            # For each hash `h` and the list of filenames with that hash `filenames`:
            filenames = db[h]
            # filenames = [filepath for filepath in db[h] if os.path.isfile(filepath)]

            # Remove duplicate filenames
            if len(set(filenames)) < len(filenames):
                print("Duplicate file names detected in hash {}, cleaning.".format(h))
                db[h] = filenames = list(set(filenames))
                # = freshening[h]
            # Verify that all these files exist.
            missing_files = []
            for filepath in filenames:
                if not os.path.isfile(filepath):
                    missing_files.append(filepath)
                else:
                    if DEBUG_FILE_EXISTS:
                        print("GOOD {}".format(filepath))

            for filepath in missing_files:
                filenames.remove(filepath)

            if DEBUG_FILE_EXISTS:
                for filepath in filenames:
                    assert os.path.isfile(filepath), filepath

            # If there is STILL more than one file with the hash:
            if len(filenames) >= threshhold:
                if sort:
                    filenames = sortDuplicatePaths(filenames)
                if not quiet:
                    print("Found {0} duplicate images for hash [{1}]".format(
                        len(filenames), h))
                if bundleHash:
                    yield (filenames, h)
                else:
                    yield filenames
    # close

    # if len(freshening.keys()) > 0:
    #     print("Adjusting {} updated records in database".format(
    #         len(freshening.keys())))
    #     with ju.Handler(shelvefile, basepath="databases", allow_writeback=True) as db:
    #         for key in freshening.keys():
    #             db[key] = freshening[key]
    #     freshening.clear()

    ju.save(fsizecache, "sizes")
    if pbar:
        pbar.finish()


def trash(file):
    print("{} -> [TRASH]".format(file))
    send2trash(file)
    print("[TRASH] <- {}".format(file))


def deleteFiles(filestodelete):
    print("Deleting files")
    if len(filestodelete) > 0:
        delSpool = loom.Spool(quota=20, delay=1, start=True)
        for file in filestodelete:
            delSpool.enqueue(
                name="trash {}".format(file),
                target=trash, args=(file,)
            )
        # Cleanup
        delSpool.finish()
        print("Finished.")


def magickCompareDuplicates(shelvefile):
    print("Running comparisons.")
    for destfldr in [shelvefile + "_sizediff", shelvefile]:
        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

    # Otherwise, do the thing.
    magickSpool = loom.Spool(quota=4, delay=1, start=True)

    for (sortedFilenames, bundledHash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=2):
        # loom.threadWait(9, 1, quiet=True)

        sizediff = (len(set([imageSize(path) for path in sortedFilenames])) > 1)

        if sizediff:
            destfldr = shelvefile + "_sizediff"
        else:
            destfldr = shelvefile

        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

        magickSpool.enqueue(name="{} | montage".format(bundledHash), target=runMagickCommand, args=(destfldr, "montage -mode concatenate", None, "compare_montage", sortedFilenames, bundledHash,))
        # montage -label %i 
        if not sizediff:
            # TODO: Detect color!
            magickSpool.enqueue(target=runMagickCommand, args=(destfldr, "compare -fuzz 10%% -compose src -highlight-color Black -lowlight-color White", None, "compare", sortedFilenames, bundledHash,))
        with open("./comparison/{}/{}_pullTrigger.sh".format(destfldr, bundledHash), "w", newline='\n') as triggerFile:
            triggerFile.write("#!/bin/bash")
            triggerFile.write("\nrm -v {}".format(" ".join('"{}"'.format(filename) for filename in sortedFilenames[1:])))
            triggerFile.write("\nrm -v ./{}*.jpg".format(bundledHash))
            triggerFile.write("\nrm -v ./{}_pullTrigger.sh".format(bundledHash))

    for destfldr in [shelvefile + "_sizediff", shelvefile]:
        with open("./comparison/{}/XXX_ALLFILES_pullTrigger_.sh".format(destfldr), "w", newline='\n') as triggerFile:
            triggerFile.write("#!/bin/bash")
            triggerFile.write(
                """\n
for trigger in *_pullTrigger.sh; do
\techo $trigger
\tbash $trigger
\trm -v $trigger 2>/dev/null
done
""")
            triggerFile.write("\nrm -v ./XXX_ALLFILES_pullTrigger.sh")

    magickSpool.finish()


def runMagickCommand(shelvefile, precmd, midcmd, fileact, sortedFilenames, bundledHash):
    outfile = "./comparison/{}/{}_{}.jpg".format(shelvefile, bundledHash, fileact)
    command = ["magick"]
    command += precmd.split(" ")
    command += sortedFilenames
    if midcmd != "" and midcmd is not None:
        command += midcmd.split(" ")
    command.append(outfile)
    # print(command)
    # print("\n".join(command))
    subprocess.call(command)


def renameFiles(shelvefile, mock=True, clobber=False):
    print("Renaming")
    operations = []
    for (filepaths, bundledHash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=1, sort=False):
        i = 0
        # for oldFileName in sortDuplicatePaths(filepaths):
        for oldFilePath in filepaths:
            i += 1
            (oldFileDir, oldFileName) = os.path.split(oldFilePath)
        # try:
            newname = os.path.join(
                oldFileDir,
                "{hash}{suffix}.{ext}".format(
                    hash=bundledHash,
                    suffix=("_{:08X}".format(CRC32(oldFilePath)) if len(
                        filepaths) is not 1 else ""),
                    ext=oldFileName.split('.')[-1]
                )
            )
            if newname != oldFilePath:
                operations.append((oldFilePath, newname, bundledHash,))
        # except FileNotFoundError:
        #     traceback.print_exc()
        #     print(bundledHash)
        #     print(filepaths)
        #     print(oldFileName)
        #     continue

    print("Processing {} file rename operations.".format(len(operations)))
    if len(operations) > 0:
        successfulOperations = []
        # Create undo file
        ufilename = "undorename_{}_{}.sh".format(shelvefile, str(int(time())))
        print("Creating undo file at {}".format(ufilename))
        with open(ufilename, "w+", newline='\n') as scriptfile:
            scriptfile.write("#!/bin/bash\n")
            for (old, new, bundledHash) in operations:
                scriptfile.write('mv -v "{new}" "{old}" # 8^y\n'.format(
                    old=old, new=new))

        # Rename files
        print("Performing disk operations")
        for (old, new, bundledHash) in operations:
            try:
                if mock:
                    raise NotImplementedError
                if os.path.isfile(new):
                    if not clobber:
                        # Collide
                        print("{} -X>< {}".format(old, new))
                        continue
                    else:
                        print("(Overwriting)")
                        loom.thread(name="[TRASH] <-- {}".format(new), target=send2trash(new))
                # Perform move
                shutil.move(old, new)
                print("{} ---> {}".format(old, new))
                successfulOperations.append((old, new, bundledHash,))
            except (FileNotFoundError, NotImplementedError) as e:
                print("{} -X-> {}".format(old, new))

        # Write new filename to database
        print("Adding new files to database")
        with ju.Handler(shelvefile, basepath="databases", allow_writeback=True) as db:
            for (old, new, bundledHash) in successfulOperations:
                dbentry = db.get(bundledHash, [])
                dbentry.remove(old)
                dbentry.append(new)
                db[bundledHash] = dbentry


def parse_args():
    """
    Parse args from command line and return the namespace
    """
    DEFAULT_HASH_SIZE = 12
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "-f", "--files", nargs='+', required=True, 
        help="File globs that select which files to check. Globstar supported.")
    ap.add_argument(
        "-s", "--shelve",
        required=True, help="Database name")
    ap.add_argument(
        "--noscan", action="store_true",
        help="Don't search the paths in --files at all, just read a previously generated database.")
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
        "-a", "--avoid", nargs='+', default=[], 
        help="Substrings in the path to penalize during file sorting.")
    ap.add_argument(
        "--clobber",
        help="Allow overwriting files during rename.", action="store_true")

    ap.add_argument(
        "-r", "--rename", action="store_true",
        help="Rename files to their perceptual hash, ordering them by similarity.")
    ap.add_argument(
        "-d", "--delete", action="store_true",
        help="Delete duplicate files by moving them to a temporary directory.")
    ap.add_argument(
        "-c", "--compare", action="store_true", 
        help="Generate imagemagick commands to compare \"duplicates\".")

    ap.add_argument(
        "--debug_hash", action="store_true",
        help="Print debugging information for hashes. Default: {}".format(HASHDEBUG))
    ap.add_argument(
        "--debug_sort", action="store_true",
        help="Print debugging information for sorting. Default: {}".format(SORTDEBUG))
    ap.add_argument(
        "--debug_exists", action="store_true",
        help="Print debugging information for file verification. Default: {}".format(DEBUG_FILE_EXISTS))
    ap.add_argument(
        "--verbose", action="store_true",
        help="Print additional information. By default, 'quiet' is: {}".format(GLOBAL_QUIET_DEFAULT))
    ap.add_argument(
        "--noprogress", action="store_true",
        help="Disallow progress bars. Default progressbar state: {}".format(PROGRESSBAR_ALLOWED))
    # ap.add_argument("--nocheck", help="Don't search the database for duplicates, just fingerprint the files in --dataset.",
    #                 action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()

    global HASHDEBUG, SORTDEBUG, GLOBAL_QUIET_DEFAULT
    global DEBUG_FILE_EXISTS, PROGRESSBAR_ALLOWED
    global BAD_WORDS
    HASHDEBUG = args.debug_hash
    SORTDEBUG = args.debug_sort
    DEBUG_FILE_EXISTS = args.debug_exists
    GLOBAL_QUIET_DEFAULT = not args.verbose
    PROGRESSBAR_ALLOWED = not args.noprogress
    BAD_WORDS = args.avoid

    shelvefile = "{0}.s{1}".format(args.shelve, args.hashsize)

    # Scan directories for files and populate database
    if not args.noscan:
        print("Crawling for files... (Use --noscan to skip this step)")
        imagePaths = sum([glob.glob(a, recursive=True) for a in args.files], [])
        # File handling and fallbacks

        def scan():
            scanDirs(shelvefile, imagePaths,
                     recheck=args.recheck,
                     hash_size=args.hashsize)
        extensions = ["json", "dir", "bak", "dat"]
        try:
            scan()
        except Exception as e:
            print("Database corrupted. Restoring.")
            for databaseFile in ["databases/{}.{}".format(shelvefile, ext) for ext in extensions]:
                try:
                    shutil.os.remove(databaseFile)
                except FileNotFoundError as e:
                    pass
            for ext in extensions:
                try:
                    shutil.copy2("databases/BAK.{}.{}".format(shelvefile, ext),
                                 "databases/{}.{}".format(shelvefile, ext))
                except FileNotFoundError as e:
                    pass
            scan()
        print("Backing up database.")
        for ext in extensions:
            try:
                shutil.copy2("databases/{}.{}".format(shelvefile, ext),
                             "databases/BAK.{}.{}".format(shelvefile, ext))
            except FileNotFoundError as e:
                pass

    # Run commands as requested
    if args.rename:
        renameFiles(shelvefile, mock=args.mock, clobber=args.clobber)

    if args.compare:
        magickCompareDuplicates(shelvefile)

    if args.delete:
        filesToDelete = getDuplicatesToDelete(
            shelvefile,
            interactive=args.interactive)
        if not args.mock:
            deleteFiles(filesToDelete)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        traceback.print_exc()
        raise
