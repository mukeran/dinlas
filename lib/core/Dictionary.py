# coding: utf-8

from random import randrange


class Dictionary:
    def __init__(self, entries):
        self.entries = entries

    @staticmethod
    def preset(name):
        with open('../../dictionary/{}.txt'.format(name)) as f:
            return Dictionary(f.readlines())

    @staticmethod
    def custom(path):
        with open(path) as f:
            return Dictionary(f.readlines())

    def random(self, limit):
        for i in range(0, limit):
            yield self.entries[randrange(0, len(self.entries))]
