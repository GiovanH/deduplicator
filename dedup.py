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

fsizecache = ju.load("sizes", default=dict())
 
hasher = hashlib.md5()

VALID_IMAGE_EXTENSIONS = ["gif", "jpg", "png", "jpeg", "bmp"]

# Image.MAX_IMAGE_PIXELS = 148306125
Image.MAX_IMAGE_PIXELS = 160000000


def md5(path):
    with open(path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


def CRC32(filename):
    buf = open(filename, 'rb').read()
    buf = (crc32(buf) & 0xFFFFFFFF)
    return "{:08X}".format(buf)
#     return "%08X" % buf


def isImage(filename):
    try:
        return filename.split(".")[-1].lower() in VALID_IMAGE_EXTENSIONS
    except IndexError:
        # No extension
        return False


def isVideo(filename):
    try:
        return filename.split(".")[-1].lower() in ["webm", "mp4"]
    except IndexError:
        # No extension
        return False


IScachetotal = IScachefails = 0


def imageSize(filename, quiet=False):
    # Get a sortable integer representing the number of pixels in an image.
    # assert os.path.isfile(filename), filename
    if not isImage(filename):
        if not quiet:
            print("Unrecognized image format:", filename)
        return 0
    h4sh = md5(filename)
    hit = fsizecache.get(h4sh)
    global IScachetotal
    global IScachefails
    IScachetotal += 1
    if hit:
        # print("H {:5}/{:5}".format(cachehits, (cachefails + cachehits)))
        return hit
    else:
        # print("F {:5}/{:5}".format(cachehits, (cachefails + cachehits)))
        IScachefails += 1
        if IScachefails % 8000 == 0:
            print("Too many cache misses: only {:5}/{:5} hits".format((IScachetotal - IScachefails), IScachetotal))
            ju.save(fsizecache, "sizes")

    try:
        w, h = Image.open(filename).size
        size = w * h
        fsizecache[h4sh] = size
        return size
    except Image.DecompressionBombError:
        return Image.MAX_IMAGE_PIXELS
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
    
    with ju.RotatingHandler(shelvefile, basepath="databases", readonly=False) as db:
        for key in db.keys():
            if len(db.get(key)) == 0:
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
        knownPaths = set(
            [
                item for sublist in
                ju.load(shelvefile, basepath="databases").values()
                for item in sublist
            ]
        )

    prune(shelvefile)
    # not yet implemented

    # SCAN: Scan filesystem for images and hash them.

    def fingerprintImage(db, imagePath):
        """Updates database db with phash data of image at imagePath."""

        # If we don't know the image, or if we're doing a full recheck
        if imagePath in knownPaths and not recheck:
            # print("Fingerprint skip")
            return

        # load the image and compute the difference hash
        try:
            if isVideo(imagePath):
                proc_hash = md5(imagePath)
            elif not isImage(imagePath):
                print("Unrecognized file format:", imagePath)
                return
            else:            
                image = Image.open(imagePath)
                proc_hash = str(imagehash.dhash(image, hash_size=hash_size))
                # Compress:
                # proc_hash = proc_hash.decode("hex").encode("base64")

        except FileNotFoundError:
            print("WARNING! File not found: ", imagePath)
            # traceback.print_exc()
            return
        except ValueError:
            print("WARNING! Error parsing image: ", imagePath)
            traceback.print_exc()
            return
        except OSError:
            print("ERROR: File", imagePath, "is corrupt or invalid.")
            print("Trashing file.")
            try:
                trash(imagePath)
            except Exception:
                # traceback.print_exc(limit=1)
                print("...but it failed!")
                pass  # Not a dealbreaker.
            return

        filename = imagePath  # [imagePath.rfind("/") + 1:]

        # Add the path to the database if it's not already present.
        # Each Key (a hash) has a List value.
        # The list is a list of file paths with that hash.
        if filename not in db.get(proc_hash, []):
            if HASHDEBUG:
                print("New file:", imagePath, proc_hash)
            db[proc_hash] = db.get(proc_hash, []) + [filename]

    print("Fingerprinting images with hash size {}".format(hash_size))
    with ju.RotatingHandler(shelvefile, default=dict(), basepath="databases", readonly=False) as db:
        with loom.Spool(6, name="Fingerprint") as fpSpool:
            # Show a pretty progress bar
            for imagePath in imagePaths:
                fpSpool.enqueue(target=fingerprintImage, args=(db, imagePath,))


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
    print("Generating information about duplicate images from database")

    with ju.RotatingHandler(shelvefile, basepath="databases", readonly=False) as db:

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
            if sort and len(filenames) >= threshhold:
                filenames = sortDuplicatePaths(filenames)
            if len(filenames) >= threshhold:
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
    #     with ju.Handler(shelvefile, basepath="databases", readonly=False) as db:
    #         for key in freshening.keys():
    #             db[key] = freshening[key]
    #     freshening.clear()

    if pbar:
        pbar.finish()


def trash(file, verbose=True):

    assert os.path.isfile(file)  # We are asked to delete a real file.
    try:
        send2trash(file)
        if verbose:
            print("{} -> [TRASH]".format(file))
    except (PermissionError, FileNotFoundError) as e:
        if not os.path.isfile(file):
            # Well, the file's gone, anyway.
            print("TRASH ODDITY: {}".format(file))
            return

        # The file is still here.
        if isinstance(e, FileNotFoundError):
            print("TRASH FAILED: {} (Not found)".format(file))
        raise


def deleteFiles(filestodelete):
    print("Deleting files")
    if len(filestodelete) > 0:
        delSpool = loom.Spool(20)
        for file in filestodelete:
            delSpool.enqueue(
                name="trash {}".format(file),
                target=trash, args=(file,)
            )
        # Cleanup
        delSpool.finish()
        print("Finished.")


def magickCompareDuplicates(shelvefile):

    def writeTriggerFile(destfldr, sortedFilenames, bundledHash):
        with open("./comparison/{}/{}_pullTrigger.sh".format(destfldr, bundledHash), "w", newline='\n') as triggerFile:
            triggerFile.write("#!/bin/bash")
            triggerFile.write("\nrm -v {}".format(" ".join('"{}"'.format(filename) for filename in sortedFilenames[1:])))
            triggerFile.write("\nrm -v ./{}*.jpg".format(bundledHash))
            triggerFile.write("\nrm -v ./{}_pullTrigger.sh".format(bundledHash))

    print("Running comparisons.")
    for destfldr in [shelvefile + "_sizediff", shelvefile]:
        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

    def processMagickAction(sortedFilenames, bundledHash):
        if not all(isImage(sfilepath) for sfilepath in sortedFilenames):
            # print("NOT attempting magick on files")
            # print(sortedFilenames)
            return

        sizediff = (len(set([imageSize(path) for path in sortedFilenames])) > 1)

        if sizediff:
            destfldr = shelvefile + "_sizediff"
        else:
            destfldr = shelvefile

        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

        compare_outfile = "./comparison/{}/{}_compare_montage.jpg".format(destfldr, bundledHash)
        if os.path.exists(compare_outfile):
            return

            # montageFileSize = sum(imageSize(p) for p in sortedFilenames)
            # existSize = imageSize(compare_outfile)
            # if (montageFileSize > 0) and (existSize % montageFileSize == 0) or any(s.split(".")[-1] == "gif" for s in sortedFilenames):  # Might be an exact multiple in case of gifs
            #     # print("Path", compare_outfile, "already exists, size matches, skipping.")
            #     continue
            # else:
            #     print("Overwriting comparison file", compare_outfile, imageSize(compare_outfile), "px vs", montageFileSize)
            
        if sizediff:
            # try:
            runMagickCommand(destfldr, "montage -mode concatenate", None, "compare_montage", sortedFilenames, bundledHash)
            writeTriggerFile(destfldr, sortedFilenames, bundledHash)
            # except subprocess.CalledProcessError as e:
            #     pass
            # montage -label %i 
        else: 
            # TODO: Detect color!
            # try:
            runMagickCommand(destfldr, "montage -mode concatenate", None, "compare_montage", sortedFilenames, bundledHash)
            runMagickCommand(destfldr, "compare -fuzz 10%% -compose src -highlight-color Black -lowlight-color White", None, "compare", sortedFilenames, bundledHash)
            writeTriggerFile(destfldr, sortedFilenames, bundledHash)
            # except subprocess.CalledProcessError as e:
            #     pass

    with loom.Spool(1, name="Magick") as magickSpool:
        for (sortedFilenames, bundledHash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=2):
            magickSpool.enqueue(target=processMagickAction, args=(sortedFilenames, bundledHash,))
        magickSpool.setQuota(5)  # Widen

    for destfldr in [shelvefile + "_sizediff", shelvefile]:

        # Remove orphaned files
        with loom.Spool(4, name="Trash") as trashSpool:
            # Image files
            for imgfil in glob.glob(".\\comparison\\{d}\\*.jpg".format(d=destfldr)):
                imgfil_hash = imgfil.split("\\")[-1].split("_")[0]
                hashs_images = glob.glob(".\\comparison\\{d}\\{h}_compare*.jpg".format(d=destfldr, h=imgfil_hash))
                triggerfile = "{}_pullTrigger.sh".format(imgfil_hash)
                shfil = ".\\comparison\\{d}\\{t}".format(d=destfldr, t=triggerfile)
                if (destfldr == shelvefile and len(hashs_images) != 2) or (destfldr == shelvefile + "_sizediff" and len(hashs_images) != 1):
                    print("Image", imgfil, "missing neighbors.", shfil)
                elif not os.path.isfile(shfil):
                    print("Image", imgfil, "missing shell file: ", shfil)
                else:
                    continue
                for file in hashs_images:
                    trashSpool.enqueue(target=trash, args=(file,))
            trashSpool.finish(resume=True)
            # Shell files
            for sh in glob.glob(".\\comparison\\{d}\\*.sh".format(d=destfldr)):
                sh_hash = sh.split("\\")[-1].split("_")[0]
                hashs_images = glob.glob(".\\comparison\\{d}\\{h}_compare*.jpg".format(d=destfldr, h=sh_hash))
                if len(hashs_images) == 0:
                    print("Shell file", sh_hash, "missing images", sh)
                    trashSpool.enqueue(target=trash, args=(sh,))

        # Write allfiles pulltrigger
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
    result = subprocess.run(command, capture_output=True, check=False)
    if len(result.stderr) + len(result.stdout) > 0:
        print(*((c if c.count(" ") == 0 else '"{c}"'.format(c=c)) for c in command))
        # print("OUT:", bytes(result.stdout).decode("unicode_escape"))
        print("ERR:", bytes(result.stderr).decode("unicode_escape"))
        raise subprocess.CalledProcessError(result.returncode, command, result)


def renameFiles(shelvefile, mock=True, clobber=False):
    """Processes the entire "rename files" command. 
    Given duplicate files present in the database, and their hashes, renames them. 
    File names are:
    "[PERCEPTUAL HASH]"         | if file is unique
    "[PERCEPTUAL HASH]_[CRC32]" | if file has hash collisions.
    
    Args:
        shelvefile (str): Name of database to use
        mock (bool, optional): If true, does not actually perform disk operations.
        clobber (bool, optional): Should files be overwritten?
           Due to the CRC32 check, this is usually very safe.
           As an extra precaution, overwritten files are trashed.
    
    Returns:
        Returns early if
        - There are no rename operations to attempt
    """

    # Track successful file operations
    successfulOperations = []

    # Define our function to thread
    def processRenameOperation(old, new, bundledHash, verboseSuccess=False, verboseError=True):
        """Appropriately renames files. 
        Designed to run in a thread. 
        Successful operations accumulate in list successfulOperations
        
        Args:
            old (str): Old file path
            new (str): New file path
            bundledHash (str): Perceptual hash of image at file
        """
        assert os.path.isfile(old)
        if mock:
            if verboseError:
                print("MOCK: {} -X-> {}".format(old, new))
            return
        if os.path.isfile(new):
            # Collision
            if not clobber:
                # Collide
                if verboseError:
                    print("FAILED: {} -X>< {} (file exists)".format(old, new))
            else:
                # Trash existing, then replace.
                trash(new)
        try:
            # Perform move
            shutil.move(old, new)
            print("{} ---> {}".format(old, new))
            successfulOperations.append((old, new, bundledHash,))
        except FileNotFoundError as e:
            print("MOVE FAILED: {} -X-> {} (Not found)".format(old, new))
            raise

    print("Renaming")
    with loom.Spool(8, name="Renamer") as renamer:
        for (filepaths, bundledHash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=1, sort=False):
            i = 0
            # for oldFileName in sortDuplicatePaths(filepaths):
            for oldFilePath in filepaths:
                i += 1
                (oldFileDir, oldFileName) = os.path.split(oldFilePath)
            # try:
                newFilePath = os.path.join(
                    oldFileDir,
                    "{hash}{suffix}.{ext}".format(
                        hash=bundledHash,
                        suffix=("_{}".format(CRC32(oldFilePath)) if len(
                            filepaths) is not 1 else ""),
                        ext=oldFileName.split('.')[-1]
                    )
                )
                if newFilePath != oldFilePath:
                    renamer.enqueue(target=processRenameOperation, args=(oldFilePath, newFilePath, bundledHash))


    # Create undo file
    ufilename = "undorename_{}_{}.sh".format(shelvefile, str(int(time())))
    print("Creating undo file at {}".format(ufilename))
    with open(ufilename, "w+", newline='\n') as scriptfile:
        scriptfile.write("#!/bin/bash\n")
        for (old, new, bundledHash) in successfulOperations:
            scriptfile.write('mv -v "{new}" "{old}" # 8^y\n'.format(
                old=old, new=new))

    # Write new filenames to database
    print("Adding new files to database")
    with ju.RotatingHandler(shelvefile, basepath="databases", readonly=False) as db:
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


SHELVE_FILE_EXTENSIONS = ["json"]


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

        scanDirs(shelvefile, imagePaths,
                 recheck=args.recheck,
                 hash_size=args.hashsize)

    ju.save(fsizecache, "sizes")
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

    ju.save(fsizecache, "sizes")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        traceback.print_exc()
        raise
