# coding: utf-8


class PythonStatic:
    def __init__(self):
        pass

    @staticmethod
    def meta():
        return {
            'name': 'Python static websites',
            'command': 'python-static',
            'description': 'Extension for Python static websites',
            'version': 'dev'
        }

    @staticmethod
    def modules():
        return []

    @staticmethod
    def register_command(parser):
        pass

    def exec(self):
        pass
