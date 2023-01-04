import os
# import subprocess
# from pprint import pprint
from glob import glob
import re
import snip


IMAGEEXTS = ["png", "jpg", "gif", "bmp", "jpeg", "tif", "gifv", "jfif", "tga", "pdn", "psd"]
VIDEOEXTS = ["webm", "mp4", "mov"]
imagetypes = ["*." + e for e in IMAGEEXTS]


def imageFilesIn(_dir):
    for ty in imagetypes:
        for file in glob(os.path.join(_dir, ty)):
            yield file


def fc(path):
    # globpath = os.path.join(path, "*.*")
    return len(list(imageFilesIn(path)))


def largestUnsortedDirs(base, m):
    print("{} largest unsorted directories:".format(m))
    path = os.path.join(base, "**", "unsorted", "")
    unsorted_directories = ((fc(p), p,) for p in glob(path, recursive=True))
    largeset_unsorted = sorted(unsorted_directories)

    # for (no, name) in largeset_unsorted[-m:]:
    for (no, name) in largeset_unsorted:
        print("[{:3}] {}".format(no, os.path.relpath(name, base)))
    # largeset_unsorted = subprocess.run(["bash", "-c", "shopt -s globstar; du -khc {path} | /bin/sort -hr | head -n {max}".format(path=path, max=m)], capture_output=True)
    # print(largeset_unsorted.args)
    # print(largeset_unsorted.stdout.decode("unicode_escape"))
    # # print(largeset_unsorted.stderr.decode("unicode_escape"))


def countFiles(base):
    d = dict()
    path = os.path.join(base, "**", "")
    alldirs = glob(path, recursive=True)
    for dir_ in alldirs:
        try:
            filecount = fc(dir_)
            d[dir_] = filecount
        except re.error as e:
            print(e)
            # print(path, "\n\t", dir_)
            # globals().update(locals())
    return d


def findMixed(base):
    path = os.path.join(base, "**", "")
    alldirs = glob(path, recursive=True)
    print("Mixed dirs:")
    for dir_ in alldirs:
        try:
            subs = glob(os.path.join(dir_, "*"))
            files = any(os.path.isfile(s) for s in subs)
            folders = any(os.path.isdir(s) for s in subs)
            # print(dir_, files, folders)
            mixed = files and folders
            if mixed:
                print(dir_)
        except re.error:
            print("Error printing file near", dir_)


def findDupes(base):
    path = os.path.join(base, "**", "")
    alldirs = glob(path, recursive=True)
    dirs = {}
    dirs_set = {}

    # dirs_2 = {}
    # for dir_ in alldirs:
    #     ds = tuple(set(dir_.split(os.path.sep)) - set(["F:", "unsorted"]))
    #     val = dirs_2.get(ds, [])
    #     val.append(dir_)
    #     dirs_2[ds] = val

    # from pprint import pprint
    # pprint(dirs_2)

    for dir_ in alldirs:
        (__, dirname) = os.path.split(os.path.split(dir_)[0])
        dirs[dirname] = dirs.get(dirname, []) + [dir_]

        dirset = set(dir_.split(os.path.sep)[-3:-1])
        key = sorted(dirset).__repr__()
        dirs_set[key] = dirs_set.get(key, []) + [dir_]

    for dirname in dirs:
        dupes = dirs.get(dirname)
        if len(dupes) > 1:
            print()
            print(dirname)
            print("\n".join("[{:3}] {}".format(fc(d), d) for d in dupes))

    for dirset in dirs_set:
        dupes = dirs_set.get(dirset)
        if len(dupes) > 1:
            print()
            print(dirset)
            print("\n".join("[{:3}] {}".format(fc(d), d) for d in dupes))


def fixMixed(base):
    import shutil
    path = os.path.join(base, "*", "**", "")
    alldirs = glob(path, recursive=True)
    for dir_ in alldirs:
        try:
            # print(dir_)
            subs = glob(os.path.join(dir_, "*"))
            files = any(os.path.isfile(s) for s in subs)
            folders = any(os.path.isdir(s) for s in subs)
            # print(dir_, files, folders)
            mixed = files and folders
            unsorted_subdir = os.path.join(dir_, "unsorted", "")
            has_unsorted = glob(unsorted_subdir)
            # print(has_unsorted)
            if mixed and has_unsorted:
                print(os.path.join(dir_, "*.*"), "->", unsorted_subdir)
                for file in imageFilesIn(dir_):
                    try:
                        shutil.move(file, unsorted_subdir)
                        print(file, "-->", unsorted_subdir)
                    except shutil.Error:
                        print(file, "-x>", unsorted_subdir)

        except re.error:
            print("Error printing file near", dir_)


def badFileCounts(base, min_=16, max_=400, seperate=True):
    d = countFiles(base)

    tooSmall = []
    tooLarge = []
    for dir_ in d.keys():
        # print(dir_)
        try:
            if d[dir_] < min_ and d[dir_] > 0:  # or len(os.listdir(dir_)) == 0:
                tooSmall.append((dir_, d[dir_],))
        except PermissionError:
            pass
    for dir_ in d.keys():
        if d[dir_] > max_:
            tooLarge.append((dir_, d[dir_],))

    if seperate:
        for t in [("few", tooSmall), ("many", tooLarge)]:
            print("Too {}:\n".format(t[0]) + "\n".join(
                "[{:3}] {}".format(i[1], os.path.relpath(i[0], base))
                for i in sorted(t[1], key=lambda e: (e[0], e[1]))
            ))
    else:
        print("\n".join(
            "[{:3}] {}".format(i[1], os.path.relpath(i[0], base))
            for i in sorted(tooLarge + tooSmall, key=lambda e: (e[0], e[1]))
        ))


def shortPath(base, path):
    os.path.relpath(path, base)


def allFileCounts(base):
    d = countFiles(base)
    print("\n".join(
        "[{:3}] {}".format(i[1], os.path.relpath(i[0], base))
        for i in sorted([(k, d[k],) for k in d.keys() if d[k] > 0], key=lambda e: (e[1], e[0])))
    )


def fixSmallDirs(base, max=3):
    # d = countFiles(base)
    # for k in (j for j in d if d[j] <= max and d[j] > 0):
    #     # print("[{:3}] {}".format(d[k], os.path.relpath(k, base)))
    #     unsorted_subdir = os.path.normpath(os.path.join(k, "..", "unsorted", ""))
    #     if not os.path.isdir(unsorted_subdir):
    #         continue
    #     # print(file_glob_str, "->", unsorted_subdir)
    #     for file in imageFilesIn(k):
    #         try:
    #             snip.moveFileToDir(file, unsorted_subdir)
    #         except Exception:
    #             pass
    print("Small dirs:")
    for k in glob(os.path.join(base, "**", ""), recursive=True):
        if os.path.isdir(os.path.join(k, "unsorted")):
            loose_files = [
                f for f in glob(os.path.join(k, "*.*"))
                if f.split(".")[-1].lower() in ['png', 'jpg', 'bmp', 'jpeg', 'gif', 'webm']
            ]
            num_loose_files = len(loose_files)
            if num_loose_files == 0:
                continue
            print(k)
            for oldfile in loose_files:
                try:
                    snip.moveFileToDir(oldfile, os.path.join(k, "unsorted", ""))
                except FileExistsError:
                    pass


def run(args): 
    base = os.path.normpath(args.base)
    if args.fixsmalldirs:
        fixSmallDirs(base)
    if args.fixmixed:
        fixMixed(base)
    if args.findmixed:
        findMixed(base)
    if args.all:
        allFileCounts(base)
    if args.bad:
        badFileCounts(base, args.bad_min, args.bad_max, seperate=args.seperate)
    if args.unsorted:
        largestUnsortedDirs(base, args.unsorted_no)
    if args.finddupes:
        findDupes(base)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("-b", "--base", default=".")
    ap.add_argument("--bad-max", type=int, default=200)
    ap.add_argument("--bad-min", type=int, default=6)
    ap.add_argument("--unsorted-no", type=int, default=14)
    for switch in ["all", "bad", "unsorted", "seperate", "findmixed", "fixmixed", "finddupes", "fixsmalldirs"]:
        ap.add_argument("--{}".format(switch), action="store_true")

    args = ap.parse_args()
    print(args)
    run(args)
