#!/usr/bin/env python3
# coding:utf-8

from lib.core import ArgumentParser, Controller


class Dinlas:
    def __init__(self):
        self.parser = ArgumentParser()
        self.args = self.parser.parse()
        if not self.args.__contains__('action'):
            self.parser.print_help()
            exit(1)
        self.controller = Controller(**self.args)


if __name__ == '__main__':
    Dinlas()