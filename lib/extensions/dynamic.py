# coding:utf-8
# Please notice that this extension is not finished!!!

from lib.modules.DynamicRequestFinder import DynamicRequestFinder
from lib.modules.SQLInjector import SQLInjector


class Dynamic:
    def __init__(self, **kwargs):
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Dynamic',
            'command': 'dynamic',
            'description': 'Extension for dynamic websites. (not finished yet)',
            'version': 'dev'
        }

    @staticmethod
    def modules():
        return [DynamicRequestFinder, SQLInjector]

    @staticmethod
    def register_command(parser):
        parser.add_argument('url', help='The destination url to scan')
        parser.add_argument('-C', '--cookies', default='', help='Define request cookies')
        parser.add_argument('-H', '--headless', action='store_true', help='Using headless browser')
        parser.add_argument('-B', '--browsermobproxy', metavar='Path to browsermobproxy', default='browsermobproxy',
                            help='Specify the path to browswermobproxy')

    def exec(self):
        print('The extension you selected is not finished.')
        DynamicRequestFinder(**self.args).exec()
        SQLInjector(**self.args).exec()
