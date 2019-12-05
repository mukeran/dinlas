# coding:utf-8

from tabulate import tabulate

from lib.core.Reporter import Reporter
from lib.extensions import extensions


class Controller:
    def __init__(self, parser, **kwargs):
        self.args = kwargs
        if self.args['action'] == 'start':
            if 'extension' not in self.args:
                parser.subparsers['start']['parser'].print_help()
                exit(1)
            extension = self.args['extension'](**self.args)
            extension.exec()
            reporter = Reporter(extension.reports, **self.args)
            reporter.generate()

        elif self.args['action'] == 'extensions':
            print('The installed extensions are followings:')
            table = []
            headers = ['Name', 'Command', 'Description', 'Version']
            for extension in extensions:
                meta = extension.meta()
                table.append([meta['name'], meta['command'], meta['description'], meta['version']])
            print(tabulate(table, headers, tablefmt='fancy_grid'))
        else:
            print('Unknown action {}'.format(self.args['action']))
