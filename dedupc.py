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

from snip.stream import TriadLogger
logger = TriadLogger(__name__)

SHELVE_FILE_EXTENSIONS = ["json"]


def deleteFiles(filestodelete):
    """Trash multiple files

    Args:
        filestodelete (list): File paths to delete
    """
    with snip.filesystem.Trash() as trash:
        for path in filestodelete:
            trash.delete(path)

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
        logger.info("Checking database for duplicates")
        i = 0
        for filelist in db.generateDuplicateFilelists(threshhold=2):
            # filelist = sortDuplicatePaths(filelist)
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
                        if ans is "":
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
    for (filepaths, bundled_hash) in db.generateDuplicateFilelists(bundleHash=True, threshhold=2, sort=True):
        logger.info(bundled_hash)
        lfilepaths = len(filepaths)
        tags = [" └─ " if i == lfilepaths - 1 else " ├─ " for i in range(0, lfilepaths)]
        for i, filepath in enumerate(filepaths):
            logger.info(tags[i] + filepath)
        logger.info("\n")


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

    logger.info("Renaming")
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
    logger.info("Creating undo file at {}".format(ufilename))
    with open(ufilename, "w+", newline='\n') as scriptfile:
        scriptfile.write("#!/bin/bash\n")
        for (old, new, bundled_hash) in successful_operations:
            scriptfile.write('mv -v "{new}" "{old}" # 8^y\n'.format(
                old=old, new=new))

    # Write new filenames to database
    logger.info("Adding new files to database")
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

    logger.info("Renaming")
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
    logger.info("Creating undo file at {}".format(ufilename))
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
        "-d", "--delete", action="store_true",
        help="Delete duplicate files by moving them to a temporary directory.")

    ap.add_argument(
        "--noprogress", action="store_true",
        help="Disallow progress bars.")
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

    shelvefile = "{0}.s{1}".format(args.shelve, args.hashsize)

    db = dupedb.db(shelvefile, args.avoid, args.prioritize)

    # Scan directories for files and populate database
    if args.scanfiles:
        logger.debug("Scanning for files")
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

        if args.purge:
            db.prune(keeppaths=image_paths)

        print("Fingerprinting")
        db.scanDirs(image_paths, recheck=args.recheck, hash_size=args.hashsize)

    if args.prune:
        list(db.generateDuplicateFilelists(threshhold=1, sort=False, validate=True))

    # Run commands as requested
    if args.renameDb:
        renameFilesFromDb(db, mock=args.mock, clobber=args.clobber)

    if args.renameFromPaths:
        renameFilesFromPaths(image_paths, args.hashsize, mock=args.mock, clobber=args.clobber)

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
