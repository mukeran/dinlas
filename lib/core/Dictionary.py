# coding: utf-8
import os
from random import randrange


def read_payload(root, filename):
    dir_ = '{}/dictionary/file_upload_payloads/'.format(root)
    with open(os.path.join(dir_, filename), 'rb') as fd:
        return fd.read()

class Dictionary:
    def __init__(self, entries):
        self.entries = entries

    @staticmethod
    def preset(root, name):
        with open('{}/dictionary/{}.txt'.format(root, name)) as f:
            return Dictionary(f.read().splitlines())

    @staticmethod
    def custom(path):
        with open(path) as f:
            return Dictionary(f.read().splitlines())

    def random(self, limit):
        for i in range(0, limit):
            yield self.entries[randrange(0, len(self.entries))]
