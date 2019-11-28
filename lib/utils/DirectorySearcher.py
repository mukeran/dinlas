# coding:utf-8


class DirectorySearcher:
    def __init__(self, results, **kwargs):
        self.results = results
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Directory Searcher for all',
            'version': '1.0'
        }

    def exec(self):
        pass
