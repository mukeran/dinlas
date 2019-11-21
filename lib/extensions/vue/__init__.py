# coding:utf-8

from .RequestFinder import RequestFinder
from lib.utils.SQLInjector import SQLInjector


class Vue:
    def __init__(self, **kwargs):
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Vue',
            'description': 'For websites using Vue.js',
            'version': '1.0'
        }

    @staticmethod
    def modules():
        return [RequestFinder, SQLInjector]

    def exec(self):
        RequestFinder(**self.args).exec()
        SQLInjector(**self.args).exec()
