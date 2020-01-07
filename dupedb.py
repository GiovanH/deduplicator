"""Summary

Attributes:
    VALID_IMAGE_EXTENSIONS (list): Description

Deleted Attributes:
    BAD_WORDS (list): List of substrings to avoid while sorting
    DEBUG_FILE_EXISTS (bool): Description
    GLOBAL_QUIET_DEFAULT (bool): Description
    HASHDEBUG (bool): Description
    IScachetotal (TYPE): Description
    PROGRESSBAR_ALLOWED (bool): Description
    SHELVE_FILE_EXTENSIONS (list): Description
    SORTDEBUG (bool): Description
"""
import imagehash        # Perceptual image hashing
import tqdm             # Progress bars
import os.path          # isfile() method
import traceback
from PIL import Image   # Image IO libraries
from os import sep
# from json.decoder import JSONDecodeError
from cv2 import error as cv2_error

# import shelve           # Persistant data storage
import snip.jfileutil as ju
import snip
import snip.image
from snip.loom import Spool
import itertools

from snip.stream import TriadLogger
logger = TriadLogger(__name__)

# DEBUG_FILE_EXISTS = False
VALID_IMAGE_EXTENSIONS = ["gif", "jpg", "png", "jpeg", "bmp"]

# Image.MAX_IMAGE_PIXELS = 148306125
Image.MAX_IMAGE_PIXELS = 160000000


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


def imageSize(filename):
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
        return 0


def getProcHash(file_path, hash_size):
    if isImage(file_path) or isVideo(file_path):
        if isImage(file_path):      
            image = Image.open(file_path)
        else:
            import cv2
            capture = cv2.VideoCapture(file_path)
            capture.grab()
            flag, frame = capture.retrieve()
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(frame)
        return str(imagehash.dhash(image, hash_size=hash_size))
    else:
        return snip.hash.md5file(file_path)


def makeSortTuple(x, good_words=[], bad_words=[]):
    upper = x.upper()
    return (
        -snip.image.framesInImage(x),  # High frames good
        -imageSize(x),  # High resolution good
        -sum([upper.count(w.upper()) for w in good_words]),  # Put images with good words higher
        +sum([upper.count(w.upper()) for w in bad_words]),  # Put images with bad words lower
        -os.path.getsize(x),  # High filesize good (if resolution is the same!)
        -len(x[:x.rfind(sep)]),  # Deep paths good
        -(upper.count("-") + upper.count("_") + upper.count(" "))  # Detailed filenames better
    )


class db():

    """Summary
    
    Attributes:
        bad_words (TYPE): Description
        fsizecache (TYPE): Description
        IScachetotal (TYPE): Description
        shelvefile (TYPE): Description
        sort_debug (TYPE): Description
    """
    
    def __init__(self, shelvefile, bad_words=[], good_words=[], progressbar_allowed=True):
        """Summary
        
        Args:
            shelvefile (TYPE): Description
            bad_words (list, optional): Description
            sort_debug (bool, optional): Description
        """
        super(db, self).__init__()

        self.shelvefile = shelvefile

        self.bad_words = bad_words
        self.good_words = good_words
        self.progressbar_allowed = progressbar_allowed

        self.IScachetotal = self.IScachefails = 0

        # try:
        #     self.fsizecache = ju.load("sizes", default=dict())
        # except JSONDecodeError:
        #     print("Bad fscache file, resetting. ")
        self.fsizecache = dict() 

    def getMediaSize(self, filename):
        """Summary
        
        Args:
            filename (TYPE): Description
        
        Returns:
            TYPE: Description
        """
        h4sh = snip.hash.md5file(filename)
        hit = self.fsizecache.get(h4sh)
        # self.IScachetotal
        # self.IScachefails
        # self.IScachetotal += 1
        if hit:
            return hit
        else:
            self.IScachefails += 1
            if self.IScachefails % 8000 == 0:
                logger.warn("Too many cache misses: only {:5}/{:5} hits".format((self.IScachetotal - self.IScachefails), self.IScachetotal))
                # ju.save(self.fsizecache, "sizes")

            size = imageSize(filename) if isImage(filename) else os.path.getsize(filename)
            self.fsizecache[h4sh] = size
            return size

    def sortDuplicatePaths(self, filenames):
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
            return makeSortTuple(x, self.good_words, self.bad_words)

        st = sorted(filter(os.path.isfile, filenames), key=sort)
        ju.save(self.fsizecache, "sizes")
        return st

    def updateRaw(self, old, new, hash):
        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False, default=dict()) as jdb:
            dbentry = jdb.get(hash, [])
            dbentry.remove(old)
            dbentry.append(new)
            jdb[hash] = dbentry

    def purge(self, keeppaths=[]):
        """Remove hashes without files and files that no longer exist
        
        Args:
            purge (bool, optional): Description
            paths (list, optional): Description
        """
        print("Cleaning and verifying database")

        def _pruneKey(dictionary, key):
            # Remove files that no longer exist
            dictionary[key] = list(set(filter(lambda p: p in keeppaths, dictionary[key])))

            # Remove hashes with no files
            if len(dictionary[key]) == 0:
                dictionary.pop(key)

            return

        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False, default=dict()) as jdb:
            with Spool(80, "Cleanup") as spool:
                for key in list(jdb.keys()):
                    spool.enqueue(_pruneKey, (jdb, key,))
                spool.finish()

    def scanDirs(self, image_paths, recheck=False, hash_size=16):
        """Summary
        
        Args:
            image_paths (list): List of paths to check (globbed)
            recheck (bool, optional): Don't skip known images
            hash_size (int, optional): Hash size
        """
        # Resolve glob to image paths

        # Make a list of image paths we already know about. We use this to skip images
        # that probably haven't changed.
        # If we're rechecking, we don't need to build this list at all!

        known_paths = set()

        if not recheck:
            print(self.shelvefile)
            with ju.RotatingHandler(self.shelvefile, default=dict(), basepath="databases", readonly=True) as jdb:
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
            """

            # Print statements go to the spool
            # Logger still logs debug statements

            # load the image and compute the difference hash
            try:
                proc_hash = getProcHash(image_path, hash_size)
                # Compress:
                # proc_hash = proc_hash.decode("hex").encode("base64")

            except FileNotFoundError:
                print("File not found '%s'" % image_path)
                logger.debug("File not found '%s'", image_path)
                # traceback.print_exc()
                return
            except (ValueError, cv2_error):
                print("Error parsing image '%s'" % image_path)
                print(traceback.format_exc())
                logger.debug("Error parsing image '%s'", image_path, exc_info=True)
                with open(f"badfiles_{self.shelvefile}.txt", "a", newline='\n') as shellfile:
                    shellfile.write("{} \n".format(image_path))
                    
                return
            except OSError:
                if os.path.isdir(image_path):
                    return

                print("File '%s' is corrupt or invalid." % image_path)
                logger.debug("File '%s' is corrupt or invalid.", image_path)
                with open(f"badfiles_{self.shelvefile}.txt", "a", newline='\n') as shellfile:
                    shellfile.write("{} \n".format(image_path))

                return

            filename = image_path  # [image_path.rfind("/") + 1:]

            # Add the path to the database if it's not already present.
            # Each Key (a hash) has a List value.
            # The list is a list of file paths with that hash.
            if filename not in db.get(proc_hash, []):
                logger.debug("New file: '%s' w/ hash '%s'", image_path, proc_hash)
                db[proc_hash] = db.get(proc_hash, []) + [filename]

        # Reset forcedelete script
        try:
            os.unlink(f"badfiles_{self.shelvefile}.txt")
        except FileNotFoundError:
            pass

        # Only check needed images
        images_to_fingerprint = [
            image_path for image_path in image_paths 
            if (image_path not in known_paths) or recheck
        ]
        
        # Progress and chunking
        num_images_to_fingerprint = len(images_to_fingerprint)
        chunk_size = 4000

        from math import ceil
        total_chunks = ceil(num_images_to_fingerprint / chunk_size)

        logger.info("Fingerprinting {} images with hash size {}".format(num_images_to_fingerprint, hash_size))
        for (i, image_path_chunk) in enumerate(snip.data.chunk(images_to_fingerprint, chunk_size)):
            with ju.RotatingHandler(self.shelvefile, default=dict(), basepath="databases", readonly=False) as jdb:
                with snip.loom.Spool(10, name="Fingerprint {}/{}".format(i + 1, total_chunks), belay=True) as fpSpool:
                    for image_path in image_path_chunk:
                        fpSpool.enqueue(target=fingerprintImage, args=(jdb, image_path,))

    def generateDuplicateFilelists(self, bundleHash=False, threshhold=1, sort=True, validate=True):
        """Generate lists of files which all have the same hash.
        
        Args:
            bundleHash (bool, optional): Description
            threshhold (int, optional): Description
            sort (bool, optional): Description
            progressbar_allowed (bool, optional): Description
        
        Yields:
            tuple: (list, hash) OR
            list: File paths of duplicates
        """
        logger.info("Generating information about duplicate images from database")

        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=(not validate)) as db:

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
                if validate:
                    db[key] = filenames = list(filter(os.path.isfile, set(db[key])))

                    for f1, f2 in itertools.combinations(filenames, 2):
                        if os.path.samefile(f1, f2):
                            filenames.remove(f2)

                    # Remove hashes with no files
                    if len(db[key]) == 0:
                        db.pop(key)
                        continue

                # If there is STILL more than one file with the hash:
                if len(filenames) >= threshhold:
                    if sort:
                        filenames = self.sortDuplicatePaths(filenames)
                    logger.debug("Found {0} duplicate images for hash [{1}]".format(len(filenames), key))
                    if bundleHash:
                        yield (filenames, key)
                    else:
                        yield filenames

        if pbar:
            pbar.close()
