# coding:utf-8

import importlib
import inspect

from lib.extensions import extensions, mappings


class Controller:
    def __init__(self, **kwargs):
        self.args = kwargs
        if self.args['action'] == 'start':
            ext = mappings.get(self.args['extension'])
            ext(**self.args).exec()
        elif self.args['action'] == 'extensions':
            for ext in extensions:
                meta = ext.meta()
                print('{}|{}|{}'.format(meta['name'], meta['description'], meta['version']))
        else:
            print('Unknown action {}'.format(self.args['action']))
