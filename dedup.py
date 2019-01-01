import loom             # Simple threading wrapper
import imagehash        # Perceptual image hashing
import argparse         # Argument parsing
import shelve           # Persistant data storage
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

# Todo: Replace some sep formatting with os.path.join

# Should we output debugging text about image hashes?
HASHDEBUG = False
# Should we output debugging text about sorting criteria?
SORTDEBUG = False

GLOBAL_QUIET_DEFAULT = True

DEBUG_FILE_EXISTS = False

PROGRESSBAR_ALLOWED = True


def CRC32(filename):
    buf = open(filename, 'rb').read()
    buf = (crc32(buf) & 0xFFFFFFFF)
    return buf
#     return "%08X" % buf


def imageSize(filename):
    # Get a sortable integer representing the number of pixels in an image.
    assert os.path.isfile(filename), filename
    try:
        w, h = Image.open(filename).size
        return w * h
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

    # Sorting key
    def sort(x):
        # Define our sort criteria.
        upper = x.upper()
        xtuple = (
            -imageSize(x),  # Put full resolution images higher
            -upper.rfind("F:{s}".format(s=sep)),  # Put images in drive F higher.
            upper.rfind("UNSORTED"),  # Put "unsorted" images lower
            # Put images in an exports folder lower
            upper.rfind("{s}EXPORTS{s}".format(s=sep)),
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


def scanDirs(shelvefile, imagePaths, recheck=False, hash_size=16):
    # Resolve glob to image paths

    # Make a list of image paths we already know about. We use this to skip images
    # that probably haven't changed.
    # If we're rechecking, we don't need to build this list at all!
    if not recheck:
        with shelve.open("databases/" + shelvefile, writeback=False) as db:
            knownPaths = set([item for sublist in db.values()
                              for item in sublist])

    # SCAN: Scan filesystem for images and hash them.

    print("Fingerprinting images with hash size {}".format(hash_size))
    with shelve.open("databases/" + shelvefile, writeback=True) as db:
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
    return sortDuplicatePaths(filestodelete)


def generateDuplicateFilelists(shelvefile, bundleHash=False, threshhold=1, quiet=GLOBAL_QUIET_DEFAULT):
    """Generate lists of files which all have the same hash."""
    print("Querying database for duplicate pictures.")
    with shelve.open("databases/" + shelvefile, writeback=False) as db:
        tempdb = {key: db[key] for key in db.keys()}  # Shallow copy of the shelf

    # Database for deleting records from the shelf later
    freshening = {}

    if PROGRESSBAR_ALLOWED:
        pbar = progressbar.ProgressBar(max_value=len(tempdb.keys()), redirect_stdout=True)
        i = 0

    for h in tempdb.keys():
        if PROGRESSBAR_ALLOWED:
            i += 1
            pbar.update(i)

        # For each hash `h` and the list of filenames with that hash `filenames`:
        filenames = tempdb[h]
        # filenames = [filepath for filepath in tempdb[h] if os.path.isfile(filepath)]

        # Remove duplicate filenames
        if len(set(filenames)) < len(filenames):
            print("Duplicate file names detected in hash {}, cleaning.".format(h))
            filenames = freshening[h] = list(set(filenames))

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
            freshening[h] = filenames
            if not quiet:
                print("File {} has vanished. Now aware of {} unique hashes with missing records. ".format(
                    filepath, len(freshening.keys())))
                
        # if DEBUG_FILE_EXISTS:
        for filepath in filenames:
            assert os.path.isfile(filepath), filepath

        # If there is STILL more than one file with the hash:
        if len(filenames) >= threshhold:
            if not quiet:
                print("Found {0} duplicate images for hash [{1}]".format(
                    len(filenames), h))
            if bundleHash:
                yield (filenames, h)
            else:
                yield filenames

    if len(freshening.keys()) > 0:
        print("Adjusting {} updated records in database".format(
            len(freshening.keys())))
        with shelve.open("databases/" + shelvefile, writeback=True) as db:
            for key in freshening.keys():
                db[key] = freshening[key]
        freshening.clear()

    if PROGRESSBAR_ALLOWED:
        pbar.finish()


def trash(file):
    print("{} -> [TRASH]".format(file))
    send2trash(file)
    print("[TRASH] <- {}".format(file))


def deleteFiles(filestodelete):
    print("Deleting files")
    if len(filestodelete) > 0:
        for file in filestodelete:
            loom.threadWait(20, 0.5, quiet=True)
            loom.thread(
                name="trash {}".format(file),
                target=trash, args=(file,))
    # Cleanup
    loom.threadWait(1, 0.5)
    print("Finished.")


def magickCompareDuplicates(shelvefile):
    print("Running comparisons.")
    for destfldr in [shelvefile + "_sizediff", shelvefile]:
        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

    # Otherwise, do the thing.

    for (sortedFilenames, bundledHash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=2):
        loom.threadWait(9, 1, quiet=True)

        sizediff = (len(set([imageSize(path) for path in sortedFilenames])) > 1)

        destfldr = (shelvefile if not sizediff else (shelvefile + "_sizediff"))
        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

        loom.thread(name="{} | montage".format(bundledHash), target=lambda: runMagickCommand(destfldr, "montage -label %i -mode concatenate", None, "compare_montage", sortedFilenames, bundledHash))
        if not sizediff:
            # TODO: Detect color!
            loom.thread(target=lambda: runMagickCommand(destfldr, "compare -fuzz 10%% -compose src -highlight-color Black -lowlight-color White", None, "compare", sortedFilenames, bundledHash))
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
    for (filepaths, bundledHash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=1):
        i = 0
        # for oldFileName in sortDuplicatePaths(filepaths):
        for oldFilePath in filepaths:
            i += 1
            (oldFileDir, oldFileName) = os.path.split(oldFilePath)
            try:
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
            except FileNotFoundError:
                traceback.print_exc()
                print(bundledHash)
                print(filepaths)
                print(oldFileName)
                continue

    print("Processing {} file rename operations.".format(len(operations)))
    if len(operations) > 0:
        successfulOperations = []
        # Create undo file
        ufilename = "undorename_{}_{}.sh".format(shelvefile, str(int(time())))
        print("Creating undo file at {}".format(ufilename))
        with open(ufilename, "w+") as scriptfile:
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
        with shelve.open("databases/" + shelvefile, writeback=True) as db:
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

    ap.add_argument("-s", "--shelve",
                    required=True, help="Databse name")
    ap.add_argument("-r", "--rename",
                    help="Rename files to their perceptual hash, ordering them by similarity.", action="store_true")
    ap.add_argument("-m", "--mock",
                    help="Don't actually delete or rename files, just print a log of which ones would be deleted.", action="store_true")
    ap.add_argument("-i", "--interactive",
                    help="Prompt for user selection in choosing the file to keep instead of relying on the sort algorithm.", action="store_true")
    ap.add_argument("-f", "--files", nargs='+',
                    help="File globs that select which files to check. Globstar supported.")
    ap.add_argument("-d", "--delete",
                    help="Delete duplicate files by moving them to a temporary directory.", action="store_true")
    ap.add_argument("-c", "--compare",
                    help="Generate imagemagick commands to compare \"duplicates\".", action="store_true")
    ap.add_argument("--recheck",
                    help="Re-fingerprint all files, even if they might not have changed.", action="store_true")
    ap.add_argument("--noscan",
                    help="Don't search the paths in --files at all, just read a previously generated database.", action="store_true")
    ap.add_argument("--hashsize",
                    type=int, default=DEFAULT_HASH_SIZE, help="How similar the images need to be to match. Default {}. Minimum 2. (2x2 image)".format(DEFAULT_HASH_SIZE))
    ap.add_argument("--clobber",
                    help="Allow overwriting files during rename.", action="store_true")
    # ap.add_argument("--nocheck", help="Don't search the database for duplicates, just fingerprint the files in --dataset.",
    #                 action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
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
        try:
            scan()
        except Exception as e:
            print("Database corrupted. Restoring.")
            for databaseFile in ["databases/{}.{}".format(shelvefile, ext) for ext in ["dir", "bak", "dat"]]:
                try:
                    shutil.os.remove(databaseFile)
                except FileNotFoundError as e:
                    pass
            for ext in ["dir", "bak", "dat"]:
                try:
                    shutil.copy2("databases/BAK.{}.{}".format(shelvefile, ext),
                                 "databases/{}.{}".format(shelvefile, ext))
                except FileNotFoundError as e:
                    pass
            scan()
        print("Backing up database.")
        for ext in ["dir", "bak", "dat"]:
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
