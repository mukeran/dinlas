# coding:utf-8

import argparse

from lib.extensions import extensions


class ArgumentParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="""Dinlas is a web vulnerability scanner."""
        )
        self.subparsers = {}

    def print_help(self):
        self.parser.print_help()

    def parse(self):
        subparsers = self.parser.add_subparsers()

        parser_start = subparsers.add_parser('start', help='Start scanning')
        parser_start.set_defaults(action='start')
        start_subparsers = parser_start.add_subparsers()
        self.subparsers['start'] = {
            'parser': parser_start,
            'subparsers': {}
        }
        for extension in extensions:
            meta = extension.meta()
            extension_parser = start_subparsers.add_parser(meta['command'], help=meta['description'])
            extension_parser.set_defaults(extension=extension)
            extension.register_command(extension_parser)
            self.subparsers['start']['subparsers'][meta['command']] = {
                'parser': extension_parser,
                'subparsers': {}
            }

        parser_extensions = subparsers.add_parser('extensions', help='Show extensions')
        parser_extensions.set_defaults(action='extensions')
        self.subparsers['extensions'] = {
            'parser': parser_extensions,
            'subparsers': {}
        }

        return self.parser.parse_args().__dict__
