# coding:utf-8

import argparse


class ArgumentParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="""Dinlas is a web vulnerability scanner."""
        )

    def print_help(self):
        self.parser.print_help()

    def parse(self):
        subparsers = self.parser.add_subparsers()

        parser_start = subparsers.add_parser('start', help='Start scanning')
        parser_start.set_defaults(action='start')
        parser_start.add_argument('-e', '--extension', metavar='EXT', default='default', help='Specify the extension '
                                                                                              'of the target url')
        parser_start.add_argument('url', help='The destination url to scan')
        parser_start.add_argument('-C', '--cookies', default='', help='Define request cookies')
        parser_start.add_argument('-H', '--headless', action='store_true', help='Using headless browser')

        parser_extensions = subparsers.add_parser('extensions', help='Show extensions')
        parser_extensions.set_defaults(action='extensions')
        parser_extensions.add_argument('-m', '--modules', metavar='EXT', dest='extension_to_show_modules',
                                       help='list modules of specific extension')

        return self.parser.parse_args().__dict__
