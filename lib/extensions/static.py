# coding:utf-8

from lib.utils import StaticRequestFinder, SQLInjector, WeakPasswordTester


class Static:
    def __init__(self, **kwargs):
        self.args = kwargs
        self.results = {}

    @staticmethod
    def meta():
        return {
            'name': 'Static',
            'command': 'static',
            'description': 'Extension for static websites',
            'version': '1.0'
        }

    @staticmethod
    def register_command(parser):
        parser.add_argument('url', help='The destination url to scan')
        parser.add_argument('-E', '--exclude', default=[], nargs='+', help='Exclude paths')
        parser.add_argument('--max-page-count', default=50, type=int, help='Max crawl page count')

    @staticmethod
    def modules():
        return [StaticRequestFinder, SQLInjector, WeakPasswordTester]

    def exec(self):
        StaticRequestFinder(**self.args).exec(self.results)
        SQLInjector(**self.args).exec()
        WeakPasswordTester(**self.args).exec(self.results)
