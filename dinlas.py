#!/usr/bin/env python3
# coding:utf-8

import os

from lib.core import ArgumentParser, Controller

import coloredlogs
coloredlogs.install(fmt='[%(asctime)s][%(filename)s][%(process)d][%(levelname)s] %(message)s')

VERSION = '1.0.0'


class Dinlas:
    def __init__(self, _root):
        self.root = _root
        self.parser = ArgumentParser()
        self.args = self.parser.parse()
        if 'action' not in self.args:
            self.parser.print_help()
            exit(1)
        self.args['root'] = self.root
        self.controller = Controller(self.parser, **self.args)


if __name__ == '__main__':
    root = os.path.dirname(__file__)
    Dinlas(root)
