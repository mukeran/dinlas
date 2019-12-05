# coding: utf-8

from random import randrange


def randstr(length, dictionary='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456'):
    res = ''
    for i in range(0, length):
        res += dictionary[randrange(0, len(dictionary))]
    return res


def randuuid():
    dictionary = '0123456789abcdef'
    uuid = '{}-{}-{}-{}-{}'.format(randstr(8, dictionary), randstr(4, dictionary), randstr(4, dictionary), randstr(4, dictionary), randstr(12, dictionary))
    return uuid
