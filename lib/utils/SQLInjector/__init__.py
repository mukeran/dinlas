# coding:utf-8


class SQLInjector:
    def __init__(self, **kwargs):
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'SQL Injector for all',
            'version': '1.0'
        }

    def exec(self):
        pass
