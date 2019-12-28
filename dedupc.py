import argparse         # Argument parsing
import subprocess       # Magick runner
import glob             # File globbing
from time import time   # Time IDs
import os.path          # isfile() method

import colorama

from send2trash import send2trash
import snip

import traceback
from PIL import Image
import snip.filesystem
import dupedb

SHELVE_FILE_EXTENSIONS = ["json"]


colorama.init(autoreset=False)


def print_colored(color, *args, **kwargs):
    print(*args, **kwargs)
    # print(color, *args, **kwargs)
    # print(colorama.Fore.RESET, end="")


def print_io(*args, **kwargs):
    return print_colored(colorama.Fore.CYAN, *args, **kwargs)


def print_warn(*args, **kwargs):
    return print_colored(colorama.Fore.YELLOW, *args, **kwargs)


def print_info(*args, **kwargs):
    return print_colored(colorama.Fore.WHITE, *args, **kwargs)


def print_debug(*args, **kwargs):
    return print_colored(colorama.Fore.MAGENTA, *args, **kwargs)


def print_err(*args, **kwargs):
    return print_colored(colorama.Fore.RED, *args, **kwargs)


def deleteFiles(filestodelete):
    """Trash multiple files

    Args:
        filestodelete (list): File paths to delete
    """
    with snip.filesystem.Trash() as trash:
        for path in filestodelete:
            trash.delete(path)


def magickCompareDuplicates(db):
    print("Compare depreciated; use compare.py instead")
    return
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

    def processMagickAction(sortedFilenames, bundled_hash):
        """Summary

        Args:
            sortedFilenames (TYPE): Description
            bundled_hash (TYPE): Description

        Returns:
            TYPE: Description
        """
        if not all(dupedb.isImage(sfilepath) for sfilepath in sortedFilenames):
            return

        sizediff = (len(set([db.getMediaSize(path) for path in sortedFilenames])) > 1)

        if sizediff:
            destfldr = db.shelvefile + "_sizediff"
        else:
            destfldr = db.shelvefile

        try:
            if sizediff:
                # try:
                runMagickCommand(destfldr, "montage -mode concatenate", None, "compare_!montage", sortedFilenames, bundled_hash)
                writeTriggerFile(destfldr, sortedFilenames, bundled_hash)
                # except subprocess.CalledProcessError as e:
                #     pass
                # montage -label %i
            else:
                # TODO: Detect color!
                # try:
                runMagickCommand(destfldr, "montage -mode concatenate", None, "compare_!montage", sortedFilenames, bundled_hash)
                runMagickCommand(destfldr, "compare -fuzz 10%% -compose src -highlight-color Black -lowlight-color White", None, "compare", sortedFilenames, bundled_hash)
                writeTriggerFile(destfldr, sortedFilenames, bundled_hash)
                # except subprocess.CalledProcessError as e:
                #     pass
        except UnicodeEncodeError:
            print(sortedFilenames)
            traceback.print_exc()

    # print_info("Removing orphaned comparison files")
    # for expected_images, destfldr in [(1, db.shelvefile + "_sizediff"), (2, db.shelvefile)]:

    #     with snip.loom.Spool(4, name="Trash") as trashSpool:

    #         # Shell files
    #         for sh in glob.glob(".\\comparison\\{d}\\*.sh".format(d=destfldr)):
    #             sh_hash = sh.split("\\")[-1].split("_")[0]
    #             hashs_images = glob.glob(".\\comparison\\{d}\\{h}_compare*.jpg".format(d=destfldr, h=sh_hash))
    #             if len(hashs_images) != expected_images:
    #                 print_err("Shell file", sh_hash, "missing images", sh)
    #                 trashSpool.enqueue(target=trash, args=(sh,))

    #         # Image files
    #         for imgfil in glob.glob(".\\comparison\\{d}\\*.jpg".format(d=destfldr)):
    #             imgfil_hash = imgfil.split("\\")[-1].split("_")[0]
    #             hashs_images_glob = ".\\comparison\\{d}\\{h}_compare*.jpg".format(d=destfldr, h=imgfil_hash)
    #             hashs_images = glob.glob(hashs_images_glob)

    #             triggerfile_title = "{}_pullTrigger.sh".format(imgfil_hash)
    #             shfil = ".\\comparison\\{d}\\{t}".format(d=destfldr, t=triggerfile_title)

    #             if not (len(hashs_images) == expected_images):
    #                 print_err("Image", imgfil, "missing neighbors.")
    #                 print_debug(hashs_images_glob)
    #                 print_debug(hashs_images)
    #                 print("")
    #             elif not os.path.isfile(shfil):
    #                 print_err("Image", imgfil, "missing shell file: ", shfil)
    #             else:
    #                 continue
    #             for file in filter(os.path.isfile, hashs_images):
    #                 trashSpool.enqueue(target=trash, args=(file,))
    #                 pass
    #         trashSpool.finish(resume=True)

    print_info("Running comparisons.")
    made_directories = False
    with snip.loom.Spool(1, name="Magick") as magickSpool:
        for (sortedFilenames, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=2):

            if not made_directories:
                # Make directories
                for destfldr in [db.shelvefile + "_sizediff", db.shelvefile]:
                    os.makedirs("./comparison/{}/".format(destfldr), exist_ok=True)
                    for existing_file in glob.glob("./comparison/{}/*".format(destfldr)):
                        os.unlink(existing_file)
                made_directories = True

            magickSpool.enqueue(target=processMagickAction, args=(sortedFilenames, bundled_hash,))
        magickSpool.setQuota(5)  # Widen

    if made_directories:
        for destfldr in [db.shelvefile + "_sizediff", db.shelvefile]:
            # Write allfiles pulltrigger
            print_info("Writing XXX_ALLFILES")
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

    if os.path.exists(outfile):
        # print("skip", bundled_hash)
        # return

        montageFileSize = sum(dupedb.imageSize(p) for p in sortedFilenames)
        existSize = dupedb.imageSize(outfile)
        if montageFileSize == existSize:
            # print_warn("Path", outfile, "already exists, size matches, skipping.", montageFileSize)
            return
        else:
            print_warn("Overwriting comparison file", outfile, existSize, "px vs", montageFileSize)

    command = ["magick"]
    command += precmd.split(" ")
    command += sortedFilenames
    if midcmd != "" and midcmd is not None:
        command += midcmd.split(" ")
    command.append(outfile)
    
    print_io(outfile)
    
    result = subprocess.run(command, capture_output=True, check=False)
    if len(result.stderr) + len(result.stdout) > 0:
        print_err(*((c if c.count(" ") == 0 else '"{}"'.format(c)) for c in command))
        # print("OUT:", bytes(result.stdout).decode("unicode_escape"))
        try:
            print_err("ERR:", bytes(result.stderr).decode("unicode_escape"))
        except UnicodeDecodeError:
            print_err(result.stderr)
        # raise subprocess.CalledProcessError(result.returncode, command, result).


def getDuplicatesToDelete(db, interactive=False):
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
        print_info("Checking database for duplicates")
        i = 0
        for filenames in db.generateDuplicateFilelists(threshhold=2):
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
            explanation = "\n\t" + "\n\t".join(["+ " + goingtokeep] + ["- " + f for f in goingtodelete])
            print_info(explanation)
        return filestodelete


def listDuplicates(db):
    for (filepaths, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=2, sort=True):
        print_info(bundled_hash)
        lfilepaths = len(filepaths)
        tags = [" └─ " if i == lfilepaths - 1 else " ├─ " for i in range(0, lfilepaths)]
        for i, filepath in enumerate(filepaths):
            print_info(tags[i], filepath, sep="")
        print_info("\n")


def remetaFiles(db, mock=True, clobber=False):
    """Processes the entire "remeta files" command. 
    Given duplicate files present in the database, and their hashes, remetas them. 

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
        - There are no remeta operations to attempt
    """

    import piexif

    # Define our function to thread
    def processRemetaOperation(old_path, bundled_hash, verboseSuccess=False, verboseError=True):
        """Appropriately remetas files. 
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

        if mock:
            if verboseError:
                print_info("MOCK: {} -X-> {}".format(bundled_hash, old_path))
            return

        try:
            im = Image.open(old_path)

            # print(old_path)

            if im.info.get("exif") is None:
                return

            exif_dict = piexif.load(im.info["exif"])

            field = piexif.ImageIFD.Software

            old_id = exif_dict["0th"].get(field)
            new_id = bundled_hash

            # print(old_id, new_id)
            # print(exif_dict)

            if old_id != new_id:
                exif_dict["0th"][field] = new_id
                exif_bytes = piexif.dump(exif_dict)

                print_io(old_path, bundled_hash)
                im.save(old_path, exif=exif_bytes)
            else:
                pass
        except Exception:
            print_err(traceback.format_exc())

    print_info("Setting EXIF metadata")
    with snip.loom.Spool(8, name="remeta'r") as remetar:
        for (filepaths, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=1, sort=False):
            # for old_file_name in sortDuplicatePaths(filepaths):
            for old_file_path in filepaths:
                # processRemetaOperation(old_file_path, bundled_hash)
                remetar.enqueue(target=processRemetaOperation, args=(old_file_path, bundled_hash))


def processRenameOperation(old_path, new_name, bundled_hash, successful_operations, verbose=False, mock=False, clobber=False):
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
        print_warn("MOCK: {} -X-> {}".format(old_path, new_path))
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


def renameFilesFromDb(db, mock=True, clobber=False):
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

    print_info("Renaming")
    with snip.loom.Spool(8, name="Renamer") as renamer:
        for (filepaths, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=1, sort=False):
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
                    suffix=("_{}".format(snip.hash.CRC32(old_file_path)) if len(filepaths) is not 1 else ""),
                    ext=old_file_name.split('.')[-1]
                )
                if new_file_name != old_file_name:
                    renamer.enqueue(
                        target=processRenameOperation,
                        args=(old_file_path, new_file_name, bundled_hash, successful_operations),
                        kwargs={"mock": mock, "clobber": clobber}
                    )

    # Create undo file
    os.makedirs("undo", exist_ok=True)
    ufilename = "undo/undorename_{}_{}.sh".format(db.shelvefile, str(int(time())))
    print_io("Creating undo file at {}".format(ufilename))
    with open(ufilename, "w+", newline='\n') as scriptfile:
        scriptfile.write("#!/bin/bash\n")
        for (old, new, bundled_hash) in successful_operations:
            scriptfile.write('mv -v "{new}" "{old}" # 8^y\n'.format(
                old=old, new=new))

    # Write new filenames to database
    print_info("Adding new files to database")
    for (old, new, bundled_hash) in successful_operations:
        db.updateRaw(old, new, bundled_hash)


def renameFilesFromPaths(filepaths, hash_size, mock=True, clobber=False):
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

    i = 0

    print_info("Renaming")
    with snip.loom.Spool(8, name="Renamer") as renamer:
        for old_file_path in filepaths:
            if old_file_path.find("!") > -1:
                continue

            i += 1
            (old_file_dir, old_file_name) = os.path.split(old_file_path)
            try:
                proc_hash = dupedb.getProcHash(old_file_path, hash_size)
                new_file_name = "{hash}{suffix}.{ext}".format(
                    hash=proc_hash,
                    suffix=("_{}".format(snip.hash.CRC32(old_file_path)) if len(filepaths) is not 1 else ""),
                    ext=old_file_name.split('.')[-1]
                )
                if new_file_name != old_file_name:
                    renamer.enqueue(
                        target=processRenameOperation,
                        args=(old_file_path, new_file_name, proc_hash, successful_operations),
                        kwargs={"mock": mock, "clobber": clobber}
                    )
            except AssertionError:
                traceback.print_exc()
                continue

    # Create undo file
    os.makedirs("undo", exist_ok=True)
    ufilename = "undo/undorename_manual_{}.sh".format(str(int(time())))
    print_io("Creating undo file at {}".format(ufilename))
    with open(ufilename, "w+", newline='\n') as scriptfile:
        scriptfile.write("#!/bin/bash\n")
        for (old, new, bundled_hash) in successful_operations:
            scriptfile.write('mv -v "{new}" "{old}" # 8^y\n'.format(
                old=old, new=new))


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
        "--purge", action="store_true",
        help="Delete records of files not currently seen, even if they're in the database.")
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
        "-a", "--avoid", nargs='+', default=[],
        help="Substrings in the path to penalize during file sorting.")
    ap.add_argument(
        "-p", "--prioritize", nargs='+', default=[],
        help="Substrings in the path to prioritize during file sorting.")
    ap.add_argument(
        "--clobber",
        help="Allow overwriting files during rename.", action="store_true")

    ap.add_argument(
        "-l", "--list", action="store_true",
        help="Show duplicate information on screen.")
    ap.add_argument(
        "-r", "--renameDb", action="store_true",
        help="Rename files to their perceptual hash, ordering them by similarity. Renames all images in DB.")
    ap.add_argument(
        "--renameFromPaths", action="store_true",
        help="Rename files to their perceptual hash, ordering them by similarity. Only use images passed directly, not the database.")
    ap.add_argument(
        "-e", "--remeta", action="store_true",
        help="Set EXIF data")
    ap.add_argument(
        "-d", "--delete", action="store_true",
        help="Delete duplicate files by moving them to a temporary directory.")
    ap.add_argument(
        "-c", "--compare", action="store_true",
        help="Generate imagemagick commands to compare \"duplicates\".")

    ap.add_argument(
        "--debug", action="store_true",
        help="Print debugging information for hashes.")
    ap.add_argument(
        "--verbose", action="store_true",
        help="Print additional information.")
    ap.add_argument(
        "--noprogress", action="store_true",
        help="Disallow progress bars.")
    ap.add_argument(
        "--noprune", action="store_true",
        help="Do not remove stale records from database. Opposite of purge.")
    # ap.add_argument("--nocheck", help="Don't search the database for duplicates, just fingerprint the files in --dataset.",
    #                 action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()

    shelvefile = "{0}.s{1}".format(args.shelve, args.hashsize)

    db = dupedb.db(shelvefile, args.avoid, args.prioritize, debug=args.debug, verbose=args.verbose)

    # Scan directories for files and populate database
    if args.scanfiles:
        print_debug("Building filelists")
        # print(args.files)
        _image_paths = sum([glob.glob(a, recursive=True) for a in args.scanfiles], [])

        # for k in _image_paths:
        #     print(k, *((j, k.find(j) == -1,) for j in args.files_exempt))

        image_paths = [
            os.path.normpath(path) for path in
            _image_paths
            if all(path.find(j) == -1 for j in args.files_exempt)
        ]

        # File handling and fallbacks

        if not args.noprune:
            db.prune(purge=args.purge, keeppaths=image_paths)

        db.scanDirs(image_paths, recheck=args.recheck, hash_size=args.hashsize)

    # Run commands as requested

    if args.remeta:
        remetaFiles(db, mock=args.mock, clobber=args.clobber)

    # Run commands as requested
    if args.renameDb:
        renameFilesFromDb(db, mock=args.mock, clobber=args.clobber)

    if args.renameFromPaths:
        renameFilesFromPaths(image_paths, args.hashsize, mock=args.mock, clobber=args.clobber)

    if args.compare:
        magickCompareDuplicates(db)

    if args.delete:
        files_to_delete = getDuplicatesToDelete(db, args.interactive)
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
