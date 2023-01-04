import glob
import json
import tqdm
import pickle

cache = {}

for dbf in tqdm.tqdm(glob.glob("databases/*.json")):
    with open(dbf, "r", encoding="utf-8") as fp:
        try:
            for h, l in json.load(fp).items():
                for filepath in l:
                    cache[filepath] = h
        except:
            print("Bad file", dbf)
            continue


with open("shared_cache.pik", "wb") as fp:
    pickle.dump(cache, fp)
