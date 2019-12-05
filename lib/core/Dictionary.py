# coding: utf-8

from random import randrange


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
