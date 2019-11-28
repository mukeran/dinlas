# coding: utf-8


class PythonDynamic:
    def __init__(self):
        pass

    @staticmethod
    def meta():
        return {
            'name': 'Python dynamic websites',
            'command': 'python-dynamic',
            'description': 'Extension for Python dynamic websites',
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
