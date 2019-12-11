# coding:utf-8

import coloredlogs
import logging

logger = logging.getLogger(__name__)
coloredlogs.install(logger=logger, fmt='[%(asctime)s][%(name)s][%(process)d][%(levelname)s] %(message)s')
