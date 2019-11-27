# coding:utf-8

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


class Logger:
    def __init__(self):
        pass

    @staticmethod
    def debug(msg):
        print(DEBUG_PREFIX + str(msg) + colors.ENDC)

    @staticmethod
    def info(msg):
        print(INFO_PREFIX + str(msg) + colors.ENDC)

    @staticmethod
    def error(msg):
        print(ERROR_PREFIX + str(msg) + colors.ENDC)

    @staticmethod
    def critical(msg):
        print(CRITICAL_PREFIX + str(msg) + colors.ENDC)

    @staticmethod
    def warning(msg):
        print(WARNING_PREFIX + str(msg) + colors.ENDC)
