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
# import snip.jfileutil as ju
import snip.image
import snip.data
# from snip.loom import Spool
import itertools
# from functools import lru_cache
import re
from math import ceil
# import json
import typing

import parallel_threads

import sqlalchemy
import sqlalchemy.orm as orm

Base = orm.declarative_base()

sqlecho = False

from snip.stream import TriadLogger
logger = TriadLogger(__name__)

# DEBUG_FILE_EXISTS = False
VALID_IMAGE_EXTENSIONS = {"gif", "jpg", "png", "jpeg", "bmp", "jfif"}
VALID_VIDEO_EXTENSIONS = {"webm", "mp4"}

# Image.MAX_IMAGE_PIXELS = 148306125
Image.MAX_IMAGE_PIXELS = 160000000

def isImage(filename: str) -> bool:
    """
    Args:
        filename (str): Path to a file

    Returns:
        bool: True if the path points to an image, else False.
    """
    try:
        return os.path.splitext(filename)[-1].lower() in VALID_IMAGE_EXTENSIONS
    except IndexError:
        # No extension
        return False


def isVideo(filename: str) -> bool:
    """
    Args:
        filename (str): Path to a file

    Returns:
        bool: True if the path points to an video, else False.
    """
    try:
        return os.path.splitext(filename)[-1].lower() in VALID_VIDEO_EXTENSIONS
    except IndexError:
        # No extension
        return False

# isfile_cache: dict[str, set[str]] = {}

# def fast_isfile(path):
#     dirname, filename = os.path.split(path)
#     if not isfile_cache.get(dirname):
#         isfile_cache[dirname] = set(os.listdir(dirname))
#     # print(isfile_cache[dirname], filename)
#     return (filename in isfile_cache[dirname])
#     # os.path.isfile

fast_isfile = os.path.isfile

def pathHasGenericName(path: str) -> bool:
    path, basename = os.path.split(path)
    plainname, ext = os.path.splitext(basename)
    return any(b == plainname for b in ['unknown', 'image0']) \
        or any(basename.startswith(b) for b in []) \
        or any(b in path for b in [])


def getProcHash(file_path: str, hashsize: int, strict=True) -> str:
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
    # if CACHE.get(file_path):
    #     return CACHE.get(file_path)
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


class FileEntry(Base):
    __tablename__ = 'file_entry'
    # id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    path = sqlalchemy.Column(sqlalchemy.String, unique=True, primary_key=True)
    proc_hash = sqlalchemy.Column(sqlalchemy.String, index=True)
    size_b = sqlalchemy.Column(sqlalchemy.Integer)
    size_px = sqlalchemy.Column(sqlalchemy.Integer)


def asdict(obj) -> dict:
    return {c.key: getattr(obj, c.key) for c in sqlalchemy.inspect(obj).mapper.column_attrs}


class db():

    """The database object.

    Attributes:
        progressbar_allowed (bool): Shows a progress bar for jobs.
        shelvefile (str): The name of the shelved database file

    """

    def __init__(self, shelvefile, hashsize=None, progressbar_allowed=True, strict_mode=True):
        super(db, self).__init__()
        self.shelvefile = shelvefile

        self.engine = sqlalchemy.create_engine(f"sqlite+pysqlite:///{shelvefile}.sqlite", echo=sqlecho, pool_size=10, max_overflow=20)
        Base.metadata.create_all(self.engine)

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

    def applyJournal(self) -> None:
        with orm.Session(self.engine) as session:
            # TODO optimize statement
            for hash, path in self.journal['removed']:
                session.execute(
                    sqlalchemy.delete(FileEntry)
                    .where(FileEntry.proc_hash == hash)
                    .where(FileEntry.path == path)
                )

            session.commit()

        for hash, path in self.journal['validate']:
            self.validateHash(hash, path)

    # def updateRaw(self, old, new, hash):
    #     """Unused?

    #     Args:
    #         old (list): The old filepaths
    #         new (list): The new filepaths
    #         hash (TYPE): The hash
    #     """

    def purge(self, keeppaths=[]) -> None:
        """Remove hashes without files and files that are not in keeppaths

        Args:
            keeppaths (list, optional): Whitelist of paths that can remain
        """
        keeppaths = set(keeppaths)
        print("Removing files not in provided globs")

        with orm.Session(self.engine) as session:
            # TODO optimize statement
            # for hash, path in self.journal['removed']:
            try:
                session.execute(
                    sqlalchemy.delete(FileEntry)
                    .filter(FileEntry.path.in_(list(keeppaths)))
                )
                session.commit()
            except sqlalchemy.exc.OperationalError:
                values = session.scalars(
                    sqlalchemy.select(FileEntry)
                ).fetchall()
                for entry in tqdm.tqdm(values):
                    # print(entry)
                    if entry.path not in keeppaths:
                        print("Removing", entry.path)
                        session.delete(entry)
                session.commit()

    def scanDirs(self, image_paths: typing.Collection[str], recheck=False) -> None:
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

        known_paths: set[str] = set()

        if not recheck:
            with orm.Session(self.engine) as session:
                values = session.scalars(
                    sqlalchemy.select(FileEntry.path)
                    # .where(FileEntry)
                )
                session.commit()
            known_paths = set(values)

        # print(known_paths)
        # Prune the shelve file

        # SCAN: Scan filesystem for images and hash them.

        # Threading
        def fingerprintImage(image_path: str) -> typing.Union[None, tuple[str, str]]:
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

            if pathHasGenericName(image_path):
                logger.warning(f"File {image_path} is a generic name! Skipping")
                return

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

            return (image_path, proc_hash)
            # session.commit()

            # Add the path to the database if it's not already present.
            # Each Key (a hash) has a List value.
            # The list is a list of file paths with that hash.
            # if image_path not in jdb.get(proc_hash, []):
            #     logger.debug("New file: '%s' w/ hash '%s'", image_path, proc_hash)
            #     db[proc_hash] = jdb.get(proc_hash, []) + [image_path]
            # else:
            #     logger.debug("File: '%s' w/ hash '%s' already in db", image_path, proc_hash)

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
        chunk_size = 80

        total_chunks = ceil(num_images_to_fingerprint / chunk_size)

        logger.info("Fingerprinting {} images with hash size {}".format(num_images_to_fingerprint, self.hashsize))

        fingerprinters = tqdm.tqdm(
            iterable=enumerate(snip.data.chunk(images_to_fingerprint, chunk_size)),
            desc="Fingerprint",
            unit="chunk"
        )

        for (i, image_path_chunk) in tqdm.tqdm(fingerprinters, total=total_chunks):
            results = parallel_threads.do_work_helper(
                fingerprintImage,
                [(image_path,) for image_path in image_path_chunk]
            )
            with orm.Session(self.engine) as session:
                for (image_path, proc_hash) in filter(bool, results):
                    value_dict = dict(
                        proc_hash=proc_hash,
                        size_b=os.path.getsize(image_path),
                        size_px=imageSize(image_path)
                    )
                    session.execute(
                        sqlalchemy.dialects.sqlite.insert(FileEntry)  # type: ignore[attr-defined]
                        .values(
                            path=image_path,
                            **value_dict
                        ).on_conflict_do_update(
                            index_elements=['path'],
                            set_=value_dict
                        )
                    )
                session.commit()

    def generateDuplicateFilelists(self, bundleHash=False, threshhold: int = 1, validate=True) -> typing.Union[str, tuple[str, str]]:
        """Generate lists of files which all have the same hash.

        Args:
            bundleHash (bool, optional): Description
            threshhold (int, optional): Description
            validate (bool, optional): Description

        Yields:
            tuple: (list, hash) OR
            list: File paths of duplicates
        """
        logger.info("Generating information about duplicate images from database")

        with orm.Session(self.engine) as session:
            # FileEntry2 = orm.aliased(FileEntry)
            hashes: list[str] = session.scalars(  # type: ignore[assignment]
                session.query(
                    FileEntry.proc_hash,
                )
                .group_by(FileEntry.proc_hash)
                .having(sqlalchemy.func.count(FileEntry.proc_hash) > 1)
            )

            hashes = list(hashes)
            for key in tqdm.tqdm(hashes):
                # print("query", key)
                fileset: list[FileEntry] = [*session.scalars(
                    session.query(FileEntry)
                    .where(FileEntry.proc_hash == key)
                )]

                # print("lenset", fileset)

                if len(fileset) < threshhold:
                    continue

                filenames: list[str] = [str(entry.path) for entry in fileset]

                # Remove files that no longer exist and remove duplicate filenames
                filenames = list(filter(fast_isfile, set(filenames)))

                # print("len", filenames)

                if len(filenames) < threshhold:
                    continue

                # print("samefile?", filenames)

                for f1, f2 in itertools.combinations(filenames, 2):
                    if os.path.samefile(f1, f2):
                        logger.warning(f"File {f1} is a samefile duplicate of {f2}")
                        filenames.remove(f2)
                        with orm.Session(self.engine) as session:
                            session.execute(
                                sqlalchemy.delete(FileEntry)
                                .where(FileEntry.path == f2)
                            )
                            session.commit()

                # print("validate", filenames)

                if validate:
                    for image_path in filenames.copy():
                        if not self.validateHash(key, image_path):
                            filenames.remove(image_path)
                            with orm.Session(self.engine) as session:
                                session.execute(
                                    sqlalchemy.delete(FileEntry)
                                    .where(FileEntry.path == image_path)
                                )
                                session.commit()

                # If there is STILL more than one file with the hash:
                if len(filenames) >= threshhold:

                    #     # Do not return a reference that can modify the database
                    #     filenames = filenames.copy()

                    # logger.info(f"Sending {filenames!r}")
                    if bundleHash:
                        yield (filenames, key)
                    else:
                        yield filenames

        # if pbar:
        #     pbar.close()

    def prune(self):
        # Removes files that have disappeared

        def _prune(key):

            filenames = set()
            for filepath in db[key]:
                if fast_isfile(filepath):
                    filenames.add(filepath)
                else:
                    logger.warning("File '%s' disappeared, removing", filepath)

            for path in [*filenames]:
                if pathHasGenericName(path):
                    logger.warning(f"File {path} is a generic name! Removing")
                    filenames.remove(path)

            for f1, f2 in itertools.combinations(filenames, 2):
                if os.path.samefile(f1, f2):
                    logger.warning(f"File {f1} is a samefile duplicate of {f2}")
                    filenames.remove(f2)

            raise NotImplementedError(prune)
            # Cleanup
            # db[key] = list(filenames)

            # # Remove hashes with no files
            # if len(db[key]) == 0:
            #     db.pop(key)

        raise NotImplementedError(prune)
        # with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=True) as db:
        # dbkeys = list(sqlalchemy.keys())
        # chunk_size = 100*60*5

        # total_chunks = ceil(len(dbkeys) / chunk_size)

        # pruners = tqdm.tqdm(
        #     iterable=enumerate(snip.data.chunk(dbkeys, chunk_size)),
        #     desc="Prune",
        #     unit="chunk"
        # )

        # for (i, keychunk) in pruners:
        #     with ju.RotatingHandler(self.shelvefile, basepath="databases", readonly=False) as db:
        #         with snip.loom.Spool(20, name="Prune {}/{}".format(i + 1, total_chunks)) as spool:
        #             for key in keychunk:
        #                 spool.enqueue(_prune, (db, key,))

    def validateHash(self, expected_hash: str, image_path: str) -> bool:
        if not fast_isfile(image_path):
            with orm.Session(self.engine) as session:
                session.execute(
                    sqlalchemy.delete(FileEntry)
                    .where(FileEntry.path == image_path)
                )
                session.commit()
            return False

        try:
            real_hash = getProcHash(image_path, self.hashsize, strict=self.strict_mode)
        except OSError:
            traceback.print_exc()
            return False

        if real_hash != expected_hash:
            logger.warning(f"File {image_path} has wrong {self.hashsize}-hash: expected {expected_hash}, got {real_hash}. Replacing...")

            with orm.Session(self.engine) as session:
                session.execute(
                    sqlalchemy.update(FileEntry)
                    .where(FileEntry.path == image_path)
                    .values(proc_hash=real_hash)
                )
                session.commit()
            return False
        else:
            return True

    def fullValidate(self, threshhold=1) -> None:
        self.generateDuplicateFilelists(self, threshhold=threshhold, validate=True)
