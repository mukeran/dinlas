# coding: utf-8


class DinlasException(RuntimeError):
    def __init__(self):
        pass


class NoRequestsException(DinlasException):
    """There's no request from the former results"""
