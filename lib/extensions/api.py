# coding: utf-8


class API:
    def __init__(self):
        pass

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
        return []

    @staticmethod
    def register_command(parser):
        pass

    def exec(self):
        pass
