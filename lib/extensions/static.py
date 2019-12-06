# coding:utf-8

from lib.modules import StaticRequestFinder, SQLInjector, WeakPasswordTester, DirectorySearcher, StoredXSSDetector,\
    ReflectedXSSDetector


class Static:
    def __init__(self, **kwargs):
        self.args = kwargs
        self.results = {}
        self.reports = [{
            'title': 'Target',
            'overview': self.args['url']
        }]

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
        parser.add_argument('url', help='the destination url to scan')
        parser.add_argument('--directory-search-limit', default=100, type=int, help='max directory search limit')
        parser.add_argument('--directory-search-random', action='store_true', help='if randomly search for directory')
        parser.add_argument('-C', '--cookie', default='', help='set cookies')
        parser.add_argument('-E', '--exclude', default=[], nargs='+', help='exclude paths')
        parser.add_argument('--max-page-count', default=50, type=int, help='max crawl page count')
        parser.add_argument('-L', '--limit', default=100, type=int, help='max test password count')
        parser.add_argument('--random', action='store_true', help='if randomly test password or not')
        parser.add_argument('--username', help='set test username')
        parser.add_argument('-H', '--headless', action='store_true', help='Using headless browser')
        parser.add_argument('-B', '--browsermobproxy', metavar='Path to browsermobproxy', default='browsermobproxy',
                            help='Specify the path to browswermobproxy')

    @staticmethod
    def modules():
        return [DirectorySearcher, StaticRequestFinder, SQLInjector, StoredXSSDetector, WeakPasswordTester]

    def exec(self):
        # DirectorySearcher(self.results, self.reports, **self.args).exec()
        StaticRequestFinder(self.results, **self.args).exec()
        # SQLInjector(self.results, self.reports, **self.args).exec()
        StoredXSSDetector(self.results, self.reports, **self.args).exec()
        ReflectedXSSDetector(self.results, self.reports, **self.args).exec()
        WeakPasswordTester(self.results, self.reports, **self.args).exec()
