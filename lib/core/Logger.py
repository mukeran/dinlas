# coding:utf-8

import sys

# From https://stackoverflow.com/questions/287871/print-in-terminal-with-colors
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


DEBUG_PREFIX = colors.OKBLUE + "[DEBUG] "
ERROR_PREFIX = colors.FAIL + "[ERROR] "
INFO_PREFIX = colors.OKBLUE + colors.BOLD + "[INFO] "
CRITICAL_PREFIX = colors.FAIL + colors.UNDERLINE + colors.BOLD + "[CRITICAL] "
WARNING_PREFIX = colors.FAIL + colors.BOLD + "[WARNING] "

def get_platform():
    platforms = {
        'linux1': 'Linux',
        'linux2': 'Linux',
        'darwin': 'OS X',
        'win32': 'Windows'
    }
    if sys.platform not in platforms:
        return sys.platform

    return platforms[sys.platform]
platform = get_platform()
class Logger:
    def __init__(self):
        pass

    @staticmethod
    def debug(msg):
        if platform == 'Linux':
            print(DEBUG_PREFIX + str(msg) + colors.ENDC)
        else:
            print("[DEBUG] {}".format(msg))


    @staticmethod
    def info(msg):
        if platform == 'Linux':
            print(INFO_PREFIX + str(msg) + colors.ENDC)
        else:
            print("[INFO] {}".format(msg))


    @staticmethod
    def error(msg):
        if platform == 'Linux':
            print(ERROR_PREFIX + str(msg) + colors.ENDC)
        else:
            print("[ERROR] {}".format(msg))


    @staticmethod
    def critical(msg):
        if platform == 'Linux':
            print(CRITICAL_PREFIX + str(msg) + colors.ENDC)
        else:
            print("[CRITICAL] {}".format(msg))


    @staticmethod
    def warning(msg):
        if platform == 'Linux':
            print(WARNING_PREFIX + str(msg) + colors.ENDC)
        else:
            print("[WARNING] {}".format(msg))

