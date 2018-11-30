# deduplicator.py

```
usage: dedup.py [-h] [-f FILES [FILES ...]] -s SHELVE [--noscan] [--nocheck]
                [-d] [--recheck] [-i]

optional arguments:
  -h, --help            show this help message and exit
  -f FILES [FILES ...], --files FILES [FILES ...]
                        File globs that select which files to check. Globstar
                        supported.
  -s SHELVE, --shelve SHELVE
                        Databse name
  --noscan              Don't search the paths in --files at all, just read a
                        previously generated database.
  --nocheck             Don't search the database for duplicates, just
                        fingerprint the files in --dataset.
  -d, --makedelete      Generate a shell script to actually delete the
                        duplicate files.
  --recheck             Re-fingerprint all files, even if they might not have
                        changed.
  -i, --interactive     Prompt for user selection in choosing the file to keep
                        instead of relying on the sort algorithm.
```

