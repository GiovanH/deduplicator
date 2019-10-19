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
import progressbar      # Progress bars
import os.path          # isfile() method
import traceback
from PIL import Image   # Image IO libraries
from os import sep
from json.decoder import JSONDecodeError

# import shelve           # Persistant data storage
import snip.jfileutil as ju
import snip

# Todo: Replace some sep formatting with os.path.join

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
        print("WARNING! File not found: ", filename)
        raise FileNotFoundError(filename)
    except OSError:
        print("WARNING! OS error with file: ", filename)
        traceback.print_exc()
        return 0


def getProcHash(file_path, hash_size):
    if isImage(file_path):      
        image = Image.open(file_path)
        return str(imagehash.dhash(image, hash_size=hash_size))
    return snip.hash.md5file(file_path)


class db():

    """Summary
    
    Attributes:
        bad_words (TYPE): Description
        fsizecache (TYPE): Description
        IScachetotal (TYPE): Description
        shelvefile (TYPE): Description
        sort_debug (TYPE): Description
        verbose (TYPE): Description
    """
    
    def __init__(self, shelvefile, bad_words=[], good_words=[], debug=False, verbose=False, progressbar_allowed=True):
        """Summary
        
        Args:
            shelvefile (TYPE): Description
            bad_words (list, optional): Description
            sort_debug (bool, optional): Description
            verbose (bool, optional): Description
        """
        super(db, self).__init__()

        self.shelvefile = shelvefile

        self.bad_words = bad_words
        self.good_words = good_words
        self.debug = debug
        self.progressbar_allowed = progressbar_allowed
        self.verbose = verbose

        self.IScachetotal = self.IScachefails = 0

        try:
            self.fsizecache = ju.load("sizes", default=dict())
        except JSONDecodeError:
            print("Bad fscache file, resetting. ")
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
        self.IScachetotal
        self.IScachefails
        self.IScachetotal += 1
        if hit:
            if self.verbose:
                print("H {:5}/{:5}".format((self.IScachetotal - self.IScachefails), self.IScachetotal))
            return hit
        else:
            if self.verbose:
                print("F {:5}/{:5}".format((self.IScachetotal - self.IScachefails), self.IScachetotal))
            self.IScachefails += 1
            if self.IScachefails % 8000 == 0:
                print("Too many cache misses: only {:5}/{:5} hits".format((self.IScachetotal - self.IScachefails), self.IScachetotal))
                ju.save(self.fsizecache, "sizes")

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
            """Summary
            
            Args:
                x (TYPE): Description
            
            Returns:
                TYPE: Description
            """
            # Define our sort criteria.
            upper = x.upper()
            xtuple = (
                -self.getMediaSize(x),  # Put full resolution images higher
                -snip.image.framesInImage(x),
                -upper.count("F:{s}".format(s=sep)),  # Put images in drive F higher.
                -sum([upper.count(x.upper()) for x in self.good_words]),  # Put images with bad words higher
                sum([upper.count(x.upper()) for x in self.bad_words]),  # Put images with bad words lower
                # Put images in an exports folder lower
                upper.count("{s}EXPORTS{s}".format(s=sep)),
                # Put images with short folder paths higher
                len(x[:x.rfind(sep)]),
                upper.rfind("{s}IPAD{s}".format(s=sep)),  # Put images with iPad in the path lower
                -os.path.getsize(x)  # Put images with short total paths higher
            )
            if self.debug:
                print(*xtuple, x, sep="\t\t")
            return xtuple

        xtuple_key = [
            "-Dimensions",
            "-Frames\t",
            "-In drive F",
            "-Good words",
            "+Bad words",
            "+Exports",
            "+Treelen",
            "+Ipad\t",
            "+Filesize\t"
        ]

        if self.debug:
            print(*xtuple_key, sep="\t")
        st = sorted(filenames, key=sort)
        ju.save(self.fsizecache, "sizes")
        return st

    def updateRaw(self, old, new, hash):
        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False, default=dict()) as jdb:
            dbentry = jdb.get(hash, [])
            dbentry.remove(old)
            dbentry.append(new)
            jdb[hash] = dbentry

    def prune(self, show_pbar=True, purge=False, keeppaths=[]):
        """Remove hashes without files.
        
        Args:
            show_pbar (bool, optional): Description
            purge (bool, optional): Description
            paths (list, optional): Description
        """
        print("Removing dead hashes")
        empties = []
        
        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False, default=dict()) as jdb:
            for key in jdb.keys():
                if purge:
                    jdb[key] = [p for p in jdb.get(key) if (p in keeppaths) and os.path.isfile(p)]
                if len(jdb.get(key)) == 0:
                    empties.append(key)

            pbar = None
            if self.progressbar_allowed:
                pbar = progressbar.ProgressBar(max_value=len(empties), redirect_stdout=True) if show_pbar else None
            i = 0
            for key in empties:
                jdb.pop(key)
                if pbar:
                    i += 1
                    pbar.update(i)
                if self.verbose:
                    print("Cleared key:", key)
            if pbar:
                pbar.finish()

            ju.save(jdb, self.shelvefile, basepath="databases")

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

            # load the image and compute the difference hash
            try:
                proc_hash = getProcHash(image_path, hash_size)
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
                # traceback.print_exc(limit=2)
                print("ERROR: File", image_path, "is corrupt or invalid.")
                with open("badfiles.txt", "a", newline='\n') as shellfile:
                    shellfile.write("{} \n".format(image_path))
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
                if self.debug:
                    print("New file:", image_path, proc_hash)
                db[proc_hash] = db.get(proc_hash, []) + [filename]

        # Reset forcedelete script
        open("badfiles.txt", "w").close()

        # Only check needed images
        images_to_fingerprint = [image_path for image_path in image_paths if (image_path not in known_paths) or recheck]
        
        # Progress and chunking
        num_images_to_fingerprint = len(images_to_fingerprint)
        chunk_size = 4000

        from math import ceil
        total_chunks = ceil(num_images_to_fingerprint / chunk_size)

        print("Fingerprinting {} images with hash size {}".format(num_images_to_fingerprint, hash_size))
        for (i, image_path_chunk) in enumerate(snip.data.chunk(images_to_fingerprint, chunk_size)):
            with ju.RotatingHandler(self.shelvefile, default=dict(), basepath="databases", readonly=False) as jdb:
                with snip.loom.Spool(10, name="Fingerprint {}/{}".format(i + 1, total_chunks)) as fpSpool:
                    for image_path in image_path_chunk:
                        fpSpool.enqueue(target=fingerprintImage, args=(jdb, image_path,))

    def generateDuplicateFilelists(self, bundleHash=False, threshhold=1, sort=True):
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
        print("Generating information about duplicate images from database")

        with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False) as db:

            pbar = None
            if self.progressbar_allowed:
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
                    filenames = self.sortDuplicatePaths(filenames)
                if len(filenames) >= threshhold:
                    if self.verbose:
                        print("Found {0} duplicate images for hash [{1}]".format(
                            len(filenames), h))
                    if bundleHash:
                        yield (filenames, h)
                    else:
                        yield filenames

        if pbar:
            pbar.finish()
