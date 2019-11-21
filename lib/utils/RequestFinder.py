# coding:utf-8


class RequestFinder:
    def __init__(self, **kwargs):
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Request Finder for all',
            'version': '1.0'
        }

    def exec(self):
        pass
