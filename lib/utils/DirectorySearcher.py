# coding:utf-8

from urllib.parse import urljoin

import requests
from requests.exceptions import ConnectTimeout
from requests.exceptions import InvalidSchema


class DirectorySearcher:
    def __init__(self, results, **kwargs):
        self.args = kwargs
        self.results = results
        self.directories = []

    @staticmethod
    def meta():
        return {
            'name': 'Directory Searcher for all',
            'version': '1.0'
        }

    def exec(self):
        with open('../../dictionary/common_directory.txt') as f:
            lines = f.readlines()
            count = 0

            for line in lines:
                url = urljoin(self.args['url'], line)
                try:
                    r = requests.get(url, timeout=5)
                except ConnectTimeout:
                    continue
                except InvalidSchema:
                    continue
                if r.status_code in [200, 201, 301, 306, 401, 403]:
                    self.directories.append({
                        'path': line,
                        'status_code': r.status_code
                    })
        self.results['directories'] = self.directories

