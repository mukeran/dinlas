# coding:utf-8


class CSRFDetector:
    def __init__(self, results, **kwargs):
        self.results = results
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'CSRF Detector for all',
            'version': '1.0'
        }

    def exec(self):
        pass
