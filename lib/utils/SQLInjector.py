# coding:utf-8


class SQLInjector:
    def __init__(self, results, reports, **kwargs):
        self.args = kwargs
        self.results = results
        self.reports = reports

    @staticmethod
    def meta():
        return {
            'name': 'SQL Injector for all',
            'version': '1.0'
        }

    def exec(self):
        pass
