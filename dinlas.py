#!/usr/bin/env python3
# coding:utf-8

from lib.core import ArgumentParser, Controller


class Dinlas:
    def __init__(self):
        self.args = ArgumentParser().parse()
        self.controller = Controller(self.args)


if __name__ == '__main__':
    Dinlas()
