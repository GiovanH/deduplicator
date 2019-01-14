"""Utility functions for storing and loading json data.

Attributes:
    basepath (str): Basepath for object files.
    basepath_json (str): Basepath for json files.
    basepath_pick (str): Basepath for pickle files.
"""
import json
# import pickle
from os import makedirs, path

# Version 1.5

basepath_json = "./jobj/" 
basepath_pick = "./obj/" 


def load(filename):
    """Args:
        filename (string): Identifier for object
    
    Returns:
        Object
    """
    return json_load(filename)


def save(object, filename):
    """Args:
        object (object): Object to store
        filename (string): Identifier for object
    """
    return json_save(object, filename)


def json_load(filename, base=basepath_json):
    """Args:
        filename (string): Identifier for object
    
    Returns:
        Object
    """
    with open(base + filename + ".json", 'r') as file:
        return json.load(file)


def json_save(object, filename, base=basepath_json):
    """Args:
        object (object)
        filename (string): Identifier for object
    """
    filename = path.join(base, filename + ".json")
    makedirs(path.split(filename)[0], exist_ok=True)
    with open(filename, 'w') as file:
        json.dump(object, file, indent=4)


class Handler():

    def __init__(self, filename, default=None, basepath=basepath_json, allow_writeback=True):
        super(Handler, self).__init__()
        self.filename = filename
        self.default = default
        self.allow_writeback = allow_writeback
        self.obj = None

    def __enter__(self):
        try:
            self.obj = load(self.filename, basepath=self.basepath)
        except Exception as e:
            if self.default:
                self.obj = self.default
            else:
                raise

    def __exit__(self, type, value, traceback):
        if self.allow_writeback:
            save(self.obj, self.filename, basepath=self.basepath)
