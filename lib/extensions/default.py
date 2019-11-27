# coding:utf-8


class Default:
    def __init__(self, **kwargs):
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Default',
            'command': 'default',
            'description': 'Extension that will analyze the website\'s technique',
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
