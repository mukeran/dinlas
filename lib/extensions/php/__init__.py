# coding: utf-8


class PHP:
    def __init__(self):
        pass

    @staticmethod
    def meta():
        return {
            'name': 'PHP',
            'command': 'php',
            'description': 'Extension for PHP websites',
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
