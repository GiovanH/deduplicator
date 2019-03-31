"""Summary

Attributes:
    BAD_WORDS (list): List of substrings to avoid while sorting
    DEBUG_FILE_EXISTS (bool): Description
    GLOBAL_QUIET_DEFAULT (bool): Description
    HASHDEBUG (bool): Description
    IScachetotal (TYPE): Description
    PROGRESSBAR_ALLOWED (bool): Description
    SHELVE_FILE_EXTENSIONS (list): Description
    SORTDEBUG (bool): Description
    VALID_IMAGE_EXTENSIONS (list): Description
"""
import loom             # Simple threading wrapper
import imagehash        # Perceptual image hashing
import argparse         # Argument parsing
import glob             # File globbing
import progressbar      # Progress bars
import os.path          # isfile() method
import traceback
import subprocess       # Magick runner

from time import time   # Time IDs
from PIL import Image   # Image IO libraries
from binascii import crc32
from send2trash import send2trash
from os import sep
import hashlib
from json.decoder import JSONDecodeError

# import shelve           # Persistant data storage
import jfileutil as ju
from snip import chunk, moveFileToFile

# Todo: Replace some sep formatting with os.path.join

# Should we output debugging text about image hashes?
HASHDEBUG = False
# Should we output debugging text about sorting criteria?
SORTDEBUG = False

GLOBAL_QUIET_DEFAULT = True

DEBUG_FILE_EXISTS = False

PROGRESSBAR_ALLOWED = True

BAD_WORDS = []

try:
    fsizecache = ju.load("sizes", default=dict())
except JSONDecodeError:
    print("Bad fscache file, resetting. ")
    fsizecache = dict() 

VALID_IMAGE_EXTENSIONS = ["gif", "jpg", "png", "jpeg", "bmp"]

# Image.MAX_IMAGE_PIXELS = 148306125
Image.MAX_IMAGE_PIXELS = 160000000


def md5(path):
    """Gives the md5 hash of a file on disk.
    Args:
        path (str): Path to a file
    
    Returns:
        str: MD5 hex digest
    """
    with open(path, 'rb') as afile:
        h = hashlib.md5()
        h.update(afile.read())
        return h.hexdigest()


def CRC32(filename):
    """Gives the CRC hash of a file on disk.
    Args:
        path (str): Path to a file
    
    Returns:
        str: CRC32 hex digest
    """
    buf = open(filename, 'rb').read()
    buf = (crc32(buf) & 0xFFFFFFFF)
    return "{:08X}".format(buf)
#     return "%08X" % buf


def isImage(filename):
    """
    Args:
        filename (str): Path to a file
    
    Returns:
        bool: True if the path points to an image, else False.
    """
    try:
        return filename.split(".")[-1].lower() in VALID_IMAGE_EXTENSIONS
    except IndexError:
        # No extension
        return False


def isVideo(filename):
    """
    Args:
        filename (str): Path to a file
    
    Returns:
        bool: True if the path points to an video, else False.
    """
    try:
        return filename.split(".")[-1].lower() in ["webm", "mp4"]
    except IndexError:
        # No extension
        return False


IScachetotal = IScachefails = 0


def imageSize(filename, quiet=False):
    """
    Args:
        filename (str): Path to an image on disk
        quiet (bool, optional): Surpress printing information
    
    Returns:
        int: Pixels in image or 0 if file is not an image.
    
    Raises:
        FileNotFoundError: Path is not on disk
    """

    if isVideo(filename):
        return 0
    if not isImage(filename):
        # if not quiet:
        #     print("Unrecognized image format:", filename)
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
        raise FileNotFoundError(filename)
    except OSError:
        print("WARNING! OS error with file: ", filename)
        return 0


def sortDuplicatePaths(filenames):
    """
    Takes a list of files known to be duplicates
    and sorts them in order of "desirability"
    
    Args:
        filenames (list): List of file paths
    
    Returns:
        list: Sorted list of file paths
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


def prune(shelvefile, verbose=False, show_pbar=True, purge=False, paths=[]):
    """Remove hashes without files.
    
    Args:
        shelvefile (str): Name of database
        verbose (bool, optional): Description
        show_pbar (bool, optional): Description
    """
    print("Removing dead hashes")
    empties = []
    
    with ju.RotatingHandler(shelvefile, basepath="databases", readonly=False, default=dict()) as db:
        for key in db.keys():
            if purge:
                db[key] = [p for p in db.get(key) if (p in paths) and os.path.isfile(p)]
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
            pbar.finish()

        ju.save(db, shelvefile, basepath="databases")


def scanDirs(shelvefile, image_paths, recheck=False, hash_size=16):
    """Summary
    
    Args:
        shelvefile (str): Name of database
        image_paths (list): List of paths to check (globbed)
        recheck (bool, optional): Don't skip known images
        hash_size (int, optional): Hash size
    """
    # Resolve glob to image paths

    # Make a list of image paths we already know about. We use this to skip images
    # that probably haven't changed.
    # If we're rechecking, we don't need to build this list at all!
    if not recheck:
        print(shelvefile)
        with ju.RotatingHandler(shelvefile, default=dict(), basepath="databases", readonly=True) as db:
            known_paths = set(
                [
                    item for sublist in
                    db.values()
                    for item in sublist
                ]
            )

    # Prune the shelve file

    # SCAN: Scan filesystem for images and hash them.

    # Threading
    def fingerprintImage(db, image_path):
        """Updates database db with phash data of image at image_path.
        
        Args:
            db (TYPE): Description
            image_path (TYPE): Description
        
        Returns:
            TYPE: Description
        """

        # load the image and compute the difference hash
        try:
            if isVideo(image_path):
                proc_hash = md5(image_path)
            elif not isImage(image_path):
                # print("Unrecognized file format:", image_path)
                return
            else:            
                image = Image.open(image_path)
                proc_hash = str(imagehash.dhash(image, hash_size=hash_size))
                # Compress:
                # proc_hash = proc_hash.decode("hex").encode("base64")

        except FileNotFoundError:
            print("WARNING! File not found: ", image_path)
            # traceback.print_exc()
            return
        except ValueError:
            print("WARNING! Error parsing image: ", image_path)
            traceback.print_exc()
            return
        except OSError:
            traceback.print_exc(limit=2)
            print("ERROR: File", image_path, "is corrupt or invalid.")
            with open("forcedelete.sh", "a", newline='\n') as shellfile:
                shellfile.write("rm -vf '{}' \n".format(image_path))
            # print("Trashing file.")
            # try:
            #     trash(image_path)
            # except Exception:
            #     print("...but it failed!")
            #     traceback.print_exc(limit=1)
            #     with open("forcedelete.sh", "a", newline='\n') as shellfile:
            #         shellfile.write("rm -vf '{}' \n".format(image_path))

            #     pass  # Not a dealbreaker.
            return

        filename = image_path  # [image_path.rfind("/") + 1:]

        # Add the path to the database if it's not already present.
        # Each Key (a hash) has a List value.
        # The list is a list of file paths with that hash.
        if filename not in db.get(proc_hash, []):
            if HASHDEBUG:
                print("New file:", image_path, proc_hash)
            db[proc_hash] = db.get(proc_hash, []) + [filename]

    # Reset forcedelete script
    open("forcedelete.sh", "w").close()

    # Only check needed images
    images_to_fingerprint = [image_path for image_path in image_paths if (image_path not in known_paths) or recheck]
    
    # Progress and chunking
    num_images_to_fingerprint = len(images_to_fingerprint)
    chunk_size = 4000

    from math import ceil
    total_chunks = ceil(num_images_to_fingerprint / chunk_size)

    print("Fingerprinting {} images with hash size {}".format(num_images_to_fingerprint, hash_size))
    for (i, image_path_chunk) in enumerate(chunk(images_to_fingerprint, chunk_size)):
        with ju.RotatingHandler(shelvefile, default=dict(), basepath="databases", readonly=False) as db:
            with loom.Spool(8, name="Fingerprint {}/{}".format(i + 1, total_chunks)) as fpSpool:
                for image_path in image_path_chunk:
                    fpSpool.enqueue(target=fingerprintImage, args=(db, image_path,))


def getDuplicatesToDelete(shelvefile, interactive=False):
    """Given a database, generate a list of duplicate files to delete.
    
    Args:
        shelvefile (str): Name of database
        interactive (bool, optional): Require user confirmation
    
    Returns:
        list: List of file paths of images marked for deletion
    
    Raises:
        AssertionError: Internal error, abort
    """
    # Initialize a list of file paths to delete at the end.
    filestodelete = []

    # CHECK: Process and evalulate duplicate fingerprints.
    print("Checking database for duplicates")
    i = 0
    for filenames in generateDuplicateFilelists(shelvefile, threshhold=2, progressbar_allowed=(not interactive)):
        # filenames = sortDuplicatePaths(filenames)
        if interactive:
            # The user gets to pick the image to keep.
            # Print up a pretty menu.
            print()
            for i in range(0, len(filenames)):
                print("{0}. {1}".format(i, filenames[i]))
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
                    if ans is "":
                        ans = 0

                    index = int(ans)
                    goingtokeep = filenames[index]
                    goingtodelete = filenames[:index] + \
                        filenames[(index + 1):]
                    good_ans = True
                except ValueError:
                    print("Not a valid number. ")  # Have another go.
        else:  
            # Not interactive.
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
        print("\n\t* " + goingtokeep, *["\n\t  " + f for f in goingtodelete])
    return filestodelete


def generateDuplicateFilelists(shelvefile, bundleHash=False, threshhold=1, quiet=GLOBAL_QUIET_DEFAULT, sort=True, progressbar_allowed=True):
    """Generate lists of files which all have the same hash.
    
    Args:
        shelvefile (TYPE): Description
        bundleHash (bool, optional): Description
        threshhold (int, optional): Description
        quiet (TYPE, optional): Description
        sort (bool, optional): Description
        progressbar_allowed (bool, optional): Description
    
    Yields:
        tuple: (list, hash) OR
        list: File paths of duplicates
    """
    print("Generating information about duplicate images from database")

    with ju.RotatingHandler(shelvefile, basepath="databases", readonly=False) as db:

        pbar = None
        if progressbar_allowed:
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
            for filepath in (f for f in filenames if not os.path.isfile(f)):
                    missing_files.append(filepath)
                # else:
                #     if DEBUG_FILE_EXISTS:
                #         print("GOOD {}".format(filepath))

            for filepath in missing_files:
                filenames.remove(filepath)

            # if DEBUG_FILE_EXISTS:
            #     for filepath in filenames:
            #         assert os.path.isfile(filepath), filepath

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

    if pbar:
        pbar.finish()


def trash(file, verbose=True):
    """Send a file to trash.
    
    Args:
        file (str): Path to a file
        verbose (bool, optional)
    """
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

        os.unlink(file)
        if not os.path.isfile(file):
            raise


def deleteFiles(filestodelete):
    """Trash multiple files
    
    Args:
        filestodelete (list): File paths to delete
    """
    print("Deleting files")
    if len(filestodelete) > 0:
        delete_spool = loom.Spool(20)
        for file in filestodelete:
            delete_spool.enqueue(
                name="trash {}".format(file),
                target=trash, args=(file,)
            )
        # Cleanup
        delete_spool.finish()
        print("Finished.")


def magickCompareDuplicates(shelvefile):
    """Use imagemagick to generate comparisons.
    
    Args:
        shelvefile (str): Name of database
    """
    def writeTriggerFile(destfldr, sortedFilenames, bundled_hash):
        """Write a file to perform deletions
        
        Args:
            destfldr (str): Comparison directory
            sortedFilenames (str): Already sorted filenames
            bundled_hash (str): Common hash
        """
        with open("./comparison/{}/{}_pullTrigger.sh".format(destfldr, bundled_hash), "w", newline='\n') as triggerFile:
            triggerFile.write("#!/bin/bash")
            triggerFile.write("\n#rm -v \"{}\"".format(sortedFilenames[0]))
            triggerFile.write("\n rm -v {}".format(" ".join('"{}"'.format(filename) for filename in sortedFilenames[1:])))
            triggerFile.write("\n\nrm -v ./{}*.jpg".format(bundled_hash))
            triggerFile.write("\nrm -v ./{}_pullTrigger.sh".format(bundled_hash))

    print("Running comparisons.")

    # Make directories
    for destfldr in [shelvefile + "_sizediff", shelvefile]:
        os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)

    def processMagickAction(sortedFilenames, bundled_hash):
        """Summary
        
        Args:
            sortedFilenames (TYPE): Description
            bundled_hash (TYPE): Description
        
        Returns:
            TYPE: Description
        """
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

        compare_outfile = "./comparison/{}/{}_{}_compare_montage.jpg".format(destfldr, len(sortedFilenames), bundled_hash)
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
            runMagickCommand(destfldr, "montage -mode concatenate", None, "compare_montage", sortedFilenames, bundled_hash)
            writeTriggerFile(destfldr, sortedFilenames, bundled_hash)
            # except subprocess.CalledProcessError as e:
            #     pass
            # montage -label %i 
        else: 
            # TODO: Detect color!
            # try:
            runMagickCommand(destfldr, "montage -mode concatenate", None, "compare_montage", sortedFilenames, bundled_hash)
            runMagickCommand(destfldr, "compare -fuzz 10%% -compose src -highlight-color Black -lowlight-color White", None, "compare", sortedFilenames, bundled_hash)
            writeTriggerFile(destfldr, sortedFilenames, bundled_hash)
            # except subprocess.CalledProcessError as e:
            #     pass

    with loom.Spool(1, name="Magick") as magickSpool:
        for (sortedFilenames, bundled_hash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=2):
            magickSpool.enqueue(target=processMagickAction, args=(sortedFilenames, bundled_hash,))
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
                    print("Image", imgfil, "missing neighbors.")
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
        print("Writing XXX_ALLFILES")
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
    
    No Longer Returned:
        Returns early if
        - There are no rename operations to attempt
    """

    # Track successful file operations
    successful_operations = []

    # Define our function to thread
    def processRenameOperation(old_path, new_name, bundled_hash, verboseSuccess=False, verboseError=True):
        """Appropriately renames files. 
        Designed to run in a thread. 
        Successful operations accumulate in list successful_operations
        
        Args:
            old_path (TYPE): Description
            new_name (TYPE): Description
            bundled_hash (str): Perceptual hash of image at file
            verboseSuccess (bool, optional): Description
            verboseError (bool, optional): Description
        
        Deleted Parameters:
            old (str): Old file path
            new (str): New file path
        
        Returns:
            TYPE: Description
        """

        old_dir, old_name = os.path.split(old_path)
        new_path = os.path.join(old_dir, new_name)

        if mock:
            if verboseError:
                print("MOCK: {} -X-> {}".format(old_path, new_path))
            return

        try:
            moveFileToFile(old_path, new_path, clobber=False)
        except FileExistsError as e:
            # Implement our own clobber behavior
            if clobber:
                # Trash existing, then replace.
                trash(new_path)
                moveFileToFile(old_path, new_path, clobber=False)
        successful_operations.append((old_path, new_path, bundled_hash,))

    print("Renaming")
    with loom.Spool(8, name="Renamer") as renamer:
        for (filepaths, bundled_hash) in generateDuplicateFilelists(shelvefile, bundleHash=True, threshhold=1, sort=False):
            i = 0
            # for old_file_name in sortDuplicatePaths(filepaths):
            for old_file_path in filepaths:
                if old_file_path.find("!") > -1:
                    continue
                i += 1
                (old_file_dir, old_file_name) = os.path.split(old_file_path)
            # try:
                new_file_name = "{hash}{suffix}.{ext}".format(
                    hash=bundled_hash,
                    suffix=("_{}".format(CRC32(old_file_path)) if len(filepaths) is not 1 else ""),
                    ext=old_file_name.split('.')[-1]
                )
                if new_file_name != old_file_name:
                    renamer.enqueue(target=processRenameOperation, args=(old_file_path, new_file_name, bundled_hash))

    # Create undo file
    os.makedirs("undo", exist_ok=True)
    ufilename = "undo/undorename_{}_{}.sh".format(shelvefile, str(int(time())))
    print("Creating undo file at {}".format(ufilename))
    with open(ufilename, "w+", newline='\n') as scriptfile:
        scriptfile.write("#!/bin/bash\n")
        for (old, new, bundled_hash) in successful_operations:
            scriptfile.write('mv -v "{new}" "{old}" # 8^y\n'.format(
                old=old, new=new))

    # Write new filenames to database
    print("Adding new files to database")
    with ju.RotatingHandler(shelvefile, basepath="databases", readonly=False) as db:
        for (old, new, bundled_hash) in successful_operations:
            dbentry = db.get(bundled_hash, [])
            dbentry.remove(old)
            dbentry.append(new)
            db[bundled_hash] = dbentry


def parse_args():
    """
    Parse args from command line and return the namespace
    
    Returns:
        TYPE: Description
    """
    DEFAULT_HASH_SIZE = 12
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "-f", "--files", nargs='+', required=True, 
        help="File globs that select which files to check. Globstar supported.")
    ap.add_argument(
        "--files-exempt", nargs='+', required=False, default=list(),
        help="File substrings to ignore")
    ap.add_argument(
        "--purge", action="store_true",
        help="Delete records of files not currently seen, even if they're in the database.")
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
        # print(args.files)
        _image_paths = sum([glob.glob(a, recursive=True) for a in args.files], [])

        # for k in _image_paths:
        #     print(k, *((j, k.find(j) == -1,) for j in args.files_exempt))

        image_paths = [
            i for i in 
            _image_paths
            if all(i.find(j) == -1 for j in args.files_exempt)
        ]
        # print("\n".join(image_paths))

        # File handling and fallbacks

        prune(shelvefile, purge=args.purge, paths=image_paths)

        scanDirs(shelvefile, image_paths,
                 recheck=args.recheck,
                 hash_size=args.hashsize)

    ju.save(fsizecache, "sizes")
    # Run commands as requested
    if args.rename:
        renameFiles(shelvefile, mock=args.mock, clobber=args.clobber)

    if args.compare:
        magickCompareDuplicates(shelvefile)

    if args.delete:
        files_to_delete = getDuplicatesToDelete(
            shelvefile,
            interactive=args.interactive)
        if not args.mock:
            deleteFiles(files_to_delete)

    ju.save(fsizecache, "sizes")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        traceback.print_exc()
        raise
