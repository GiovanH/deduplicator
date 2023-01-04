"""Tools for handling a database that detects duplicate and similar files

Attributes:
    logger: logging.logger instance
    VALID_IMAGE_EXTENSIONS (list): List of extensions to consider "images"

"""
import imagehash        # Perceptual image hashing
import tqdm             # Progress bars
import os.path          # isfile() method
import traceback
from PIL import Image   # Image IO libraries
# from json.decoder import JSONDecodeError
from cv2 import error as cv2_error

# import shelve           # Persistant data storage
import snip.jfileutil as ju
import snip.image
import snip.data
from snip.loom import Spool
import itertools
from functools import lru_cache
import re
from math import ceil
import json

from snip.stream import TriadLogger
logger = TriadLogger(__name__)

# DEBUG_FILE_EXISTS = False
VALID_IMAGE_EXTENSIONS = {"gif", "jpg", "png", "jpeg", "bmp", "jfif"}

# Image.MAX_IMAGE_PIXELS = 148306125
Image.MAX_IMAGE_PIXELS = 160000000

@lru_cache()
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


@lru_cache()
def isVideo(filename):
    """
    Args:
        filename (str): Path to a file
    
    Returns:
        bool: True if the path points to an video, else False.
    """
    try:
        return filename.split(".")[-1].lower() in {"webm", "mp4"}
    except IndexError:
        # No extension
        return False

CACHE = {}
try:
    import pickle
    with open("shared_cache.pik", "rb") as fp:
        CACHE = pickle.load(fp)
except Exception:
    logger.warning("No cache", exc_info=True)

def getProcHash(file_path, hashsize, strict=True):
    """Gets a hash for a file. There are no requirements for the type of file.
    
    Args:
        file_path (TYPE): The full path to a file.
        hash_size (int): hash_size parameter for imagehash.dhash
    
    Returns:
        str: 
        If the file is an image, this will return the procedural hash.
        If the file is a video, this will return the procedural hash of the first frame.
        If the file is anything else, this returns the md5 hash of the file.
    """
    if CACHE.get(file_path):
        return CACHE.get(file_path)
    if isImage(file_path):
        if strict and snip.image.framesInImage(file_path) > 1:
            return snip.hash.md5file(file_path)

        image = Image.open(file_path)
        return str(imagehash.dhash(image, hash_size=hashsize))

    elif isVideo(file_path):
        if strict:
            return snip.hash.md5file(file_path)

        import cv2
        capture = cv2.VideoCapture(file_path)
        capture.grab()
        flag, frame = capture.retrieve()
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(frame)
        return str(imagehash.dhash(image, hash_size=hashsize))

    else:
        return snip.hash.md5file(file_path)


class db():

    """The database object.
    
    Attributes:
        progressbar_allowed (bool): Shows a progress bar for jobs.
        shelvefile (str): The name of the shelved database file
    
    """

    def __init__(self, shelvefile, hashsize=None, progressbar_allowed=True, strict_mode=True):
        super(db, self).__init__()
        self.shelvefile = shelvefile
        self.progressbar_allowed = progressbar_allowed
        self.strict_mode = strict_mode

        if hashsize == None:
            # Hack: find size from naming convention
            try:
                (hashsize,) = re.search(r"\.s(\d+)$", shelvefile).groups()
                hashsize = int(hashsize)
            except:
                print(repr(shelvefile))
                logger.error(shelvefile, exc_info=True)
        self.hashsize = hashsize
        self.journal = {
            "removed": [],
            "validate": []
        }

    def applyJournal(self):
        with ju.RotatingHandler(self.shelvefile, basepath="databases", default={}) as jdb:
            for hash, path in self.journal['removed']:
                dbentry = jdb.get(hash, [])
                if path in dbentry:
                    dbentry.remove(path)
                    jdb[hash] = dbentry    

            for hash, path in self.journal['validate']:
                self.validateHash(jdb, hash, path)

    def updateRaw(self, old, new, hash):
        """Unused?
        
        Args:
            old (list): The old filepaths
            new (list): The new filepaths
            hash (TYPE): The hash
        """
        with ju.RotatingHandler(self.shelvefile, basepath="databases", default={}) as jdb:
            dbentry = jdb.get(hash, [])
            dbentry.remove(old)
            dbentry.append(new)
            jdb[hash] = dbentry

    def purge(self, keeppaths=[]):
        """Remove hashes without files and files that are not in keeppaths
        
        Args:
            keeppaths (list, optional): Whitelist of paths that can remain
        """
        keeppaths = set(keeppaths)
        print("Removing files not in provided globs")

        with ju.RotatingHandler(self.shelvefile, basepath="databases", default={}) as jdb:
            for key in set(jdb.keys()):
                cached_paths = jdb[key]
                good_file_set = set(filter(lambda p: p in keeppaths, cached_paths))
                if good_file_set != set(jdb[key]):
                    jdb[key] = list(good_file_set)

    def scanDirs(self, image_paths, recheck=False):
        """Scans image paths and updates the database
        
        Args:
            image_paths (list): List of paths to check (globbed)
            recheck (bool, optional): Don't skip known images
            hash_size (int, optional): Hash size
            check_neighbors (bool, optional): Description
        """
        # Resolve glob to image paths

        # Make a list of image paths we already know about. We use this to skip images
        # that probably haven't changed.
        # If we're rechecking, we don't need to build this list at all!

        known_paths = set()

        if not recheck:
            with ju.RotatingHandler(self.shelvefile, default={}, basepath="databases", readonly=True) as jdb:
                known_paths = set(snip.data.flatList(jdb.values()))

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
            
            Raises:
                NotImplementedError: Description
            """

            # Print statements go to the spool
            # Logger still logs debug statements
            # load the image and compute the difference hash
            try:
                proc_hash = getProcHash(image_path, self.hashsize, strict=self.strict_mode)
                # Compress:
                # proc_hash = proc_hash.decode("hex").encode("base64")

            except MemoryError:
                logger.error("Not enough memory to handle image '%s'", image_path)
                return
            except FileNotFoundError:
                logger.error("File not found '%s'", image_path)
                return
            except (ValueError, cv2_error, SyntaxError):
                logger.error("Error parsing image '%s'", image_path, exc_info=True)
                with open(f"badfiles_{self.shelvefile}.txt", "a", newline='\n') as shellfile:
                    shellfile.write("{} \n".format(image_path))
                return
            except OSError:
                if os.path.isdir(image_path):
                    logger.debug("Image '%s' is a directory", image_path, exc_info=False)
                    return

                logger.warning("File '%s' is corrupt or invalid." % image_path)
                logger.debug("File '%s' is corrupt or invalid.", image_path)
                with open(f"badfiles_{self.shelvefile}.txt", "a", newline='\n') as shellfile:
                    shellfile.write("{} \n".format(image_path))

                return

            # if int(proc_hash, base=16) == 0:
            #     logger.warning("File: '%s' has zero hash", image_path)
            #     return

            # Add the path to the database if it's not already present.
            # Each Key (a hash) has a List value.
            # The list is a list of file paths with that hash.
            if image_path not in db.get(proc_hash, []):
                logger.debug("New file: '%s' w/ hash '%s'", image_path, proc_hash)
                db[proc_hash] = db.get(proc_hash, []) + [image_path]
            else:
                logger.debug("File: '%s' w/ hash '%s' already in db", image_path, proc_hash)

        # Reset forcedelete script
        try:
            os.unlink(f"badfiles_{self.shelvefile}.txt")
        except FileNotFoundError:
            pass

        # Only check needed images
        image_paths = set(image_paths)

        # We know that image_paths all exist, because they come from glob, probably, so no need to check them
        images_to_fingerprint = {
            image_path for image_path in image_paths
            if (image_path not in known_paths) or recheck
        }

        # Progress and chunking
        num_images_to_fingerprint = len(images_to_fingerprint)
        chunk_size = 1000

        total_chunks = ceil(num_images_to_fingerprint / chunk_size)

        logger.info("Fingerprinting {} images with hash size {}".format(num_images_to_fingerprint, self.hashsize))

        fingerprinters = tqdm.tqdm(
            iterable=enumerate(snip.data.chunk(images_to_fingerprint, chunk_size)),
            desc="Fingerprint",
            unit="chunk"
        )

        for (i, image_path_chunk) in fingerprinters:
            with ju.RotatingHandler(self.shelvefile, default={}, basepath="databases") as jdb:
                with snip.loom.Spool(10, name="Fingerprint {}/{}".format(i + 1, total_chunks), belay=True) as fpspool:
                    for image_path in image_path_chunk:
                        fpspool.enqueue(target=fingerprintImage, args=(jdb, image_path,))

    def generateDuplicateFilelists(self, bundleHash=False, threshhold=1, validate=True):
        """Generate lists of files which all have the same hash.
        
        Args:
            bundleHash (bool, optional): Description
            threshhold (int, optional): Description
            validate (bool, optional): Description
        
        Yields:
            tuple: (list, hash) OR
            list: File paths of duplicates
        
        Deleted Parameters:
            progressbar_allowed (bool, optional): Description
        """
        logger.info("Generating information about duplicate images from database")

        db_is_readonly = (not validate)

        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=db_is_readonly) as db:

            pbar = None
            if self.progressbar_allowed:
                pbar = tqdm.tqdm(
                    desc="Query",
                    total=len(db.keys()),
                    unit="hash"
                )

            for key in list(db.keys()):
                if pbar:
                    pbar.update()

                filenames = db[key]

                if len(filenames) < threshhold:
                    continue

                # Remove files that no longer exist and remove duplicate filenames

                filenames = list(filter(os.path.isfile, set(filenames)))

                for f1, f2 in itertools.combinations(filenames, 2):
                    if os.path.samefile(f1, f2):
                        logger.warning(f"File {f1} is a samefile duplicate of {f2}")
                        filenames.remove(f2)

                if validate:
                    for image_path in filenames.copy():
                        if not self.validateHash(db, key, image_path):
                            filenames.remove(image_path)

                # Cleanup
                db[key] = filenames

                # Remove hashes with no files
                if len(db[key]) == 0:
                    db.pop(key)
                    continue

                # If there is STILL more than one file with the hash:
                if len(filenames) >= threshhold:
                    # logger.debug("Found {0} duplicate images for hash [{1}]".format(len(filenames), key))
                    if not db_is_readonly:
                        # Do not return a reference that can modify the database
                        filenames = filenames.copy()

                    if bundleHash:
                        yield (filenames, key)
                    else:
                        yield filenames

        if pbar:
            pbar.close()

    def prune(self):
        # Removes files that have disappeared

        def _prune(db, key):

            filenames = set()
            for filepath in db[key]:
                if os.path.isfile(filepath):
                    filenames.add(filepath)
                else:
                    logger.warning("File '%s' disappeared, removing", filepath)

            for f1, f2 in itertools.combinations(filenames, 2):
                if os.path.samefile(f1, f2):
                    logger.warning(f"File {f1} is a samefile duplicate of {f2}")
                    filenames.remove(f2)

            # Cleanup
            db[key] = list(filenames)

            # Remove hashes with no files
            if len(db[key]) == 0:
                db.pop(key)

        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=True) as db:
            dbkeys = list(db.keys())
            chunk_size = 100*60*5

            total_chunks = ceil(len(dbkeys) / chunk_size)

            pruners = tqdm.tqdm(
                iterable=enumerate(snip.data.chunk(dbkeys, chunk_size)),
                desc="Prune",
                unit="chunk"
            )

        for (i, keychunk) in pruners:
            with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False) as db:
                with snip.loom.Spool(20, name="Prune {}/{}".format(i + 1, total_chunks)) as spool:
                    for key in keychunk:
                        spool.enqueue(_prune, (db, key,))

    def validateHash(self, jdb, expected_hash, image_path):
        if not os.path.isfile(image_path):
            # logger.warning(f"File {image_path} not found during validation!")            
            if jdb:
                dbentry = jdb.get(expected_hash, [])
                if image_path in dbentry:
                    dbentry.remove(image_path)
                    jdb[expected_hash] = dbentry
            return False

        real_hash = getProcHash(image_path, self.hashsize, strict=self.strict_mode)
        if real_hash != expected_hash:
            logger.warning(f"File {image_path} has wrong {self.hashsize}-hash: expected {expected_hash}, got {real_hash}")
            
            if jdb:
                dbentry = jdb.get(expected_hash, [])
                if image_path in dbentry:
                    dbentry.remove(image_path)
                    jdb[expected_hash] = dbentry

                dbentry = jdb.get(real_hash, [])
                dbentry.append(image_path)
                jdb[real_hash] = dbentry
            return False
        else:
            return True

    def fullValidate(self, threshhold=1):
        self.generateDuplicateFilelists(self, threshhold=threshhold, validate=True)
