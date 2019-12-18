# coding:utf-8

from urllib.parse import urljoin
import logging

import requests
from requests.exceptions import ConnectTimeout, InvalidSchema, ConnectionError

from lib.core.Dictionary import Dictionary


class DirectorySearcher:
    def __init__(self, results, reports, **kwargs):
        self.args = kwargs
        self.results = results
        self.reports = reports
        self.directories = []

    @staticmethod
    def meta():
        return {
            'name': 'Directory Searcher for all',
            'version': '1.0'
        }

    def exec(self):
        logging.info('Start to find possible hidden path')
        dictionary = Dictionary.preset(self.args['root'], 'common_directory')
        directory_search_limit = self.args['directory_search_limit']

        def entries():
            if self.args['directory_search_random']:
                for entry in dictionary.random(directory_search_limit):
                    yield entry
            else:
                for entry in dictionary.entries[:directory_search_limit]:
                    yield entry

        for line in entries():
            url = urljoin(self.args['url'], line)
            logging.info('Testing url {}'.format(url))
            try:
                r = requests.get(url, timeout=5)
            except ConnectTimeout:
                continue
            except InvalidSchema:
                continue
            except ConnectionError:
                continue
            if r.status_code in [200, 201, 301, 306, 401, 403]:
                self.directories.append({
                    'path': line,
                    'status_code': r.status_code
                })
        self.results['directories'] = self.directories
        self.reports.append({
            'title': 'Hidden Web Files/Paths',
            'overview': 'Found {} potential hidden web files/paths'.format(len(self.directories)),
            'header': ['Path', 'Status Code'],
            'entries': list(map(lambda x: [x['path'], x['status_code']], self.directories))
        })
        logging.info('Found {} potential hidden web files/paths'.format(len(self.directories)))
