# coding: utf-8
from lib.modules import SQLInjector, WeakPasswordTester


class API:
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
            'name': 'API',
            'command': 'api',
            'description': 'Extension for specific API',
            'version': '1.0'
        }

    @staticmethod
    def modules():
        return [SQLInjector, WeakPasswordTester]

    @staticmethod
    def register_command(parser):
        pass

    def exec(self):
        pass
