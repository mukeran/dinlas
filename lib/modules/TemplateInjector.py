# coding:utf-8

from urllib.parse import urljoin

import requests
import random


class TemplateInjector:
    def __init__(self, results, reports, **kwargs):
        self.results = results
        self.reports = reports
        self.args = kwargs
        self.vulnerable = []

    @staticmethod
    def meta():
        return {
            'name': 'Template Injector for all',
            'version': '1.0'
        }

    def exec(self):
        raw_url = self.results['url']
        url = set()

        for _url in raw_url:
            _url.split('?', 1)
            url.add(_url[0])

        randint1 = random.randint(32768, 65536)
        randint2 = random.randint(16384, 32768)

        randsum = randint1 + randint2

        payload = '{{' + str(randint1) + '+' + str(randint2) + '}}'
        check_str = str(randsum)

        header = {
            'User_Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.'
                          '2924.87 Safari/537.36'
        }
        for test_url in url:
            attack_dir = urljoin(test_url, payload)
            req = requests.get(attack_dir, header=header)
            if req.text.find(check_str) != -1:
                self.vulnerable.append({
                    'url': test_url,
                    'payload': payload
                })

        self.reports.append({
            'title': 'Server Side Template Injection Points',
            'overview': 'Found {} SSTI point(s)'.format(len(self.results)),
            'header': ['Path', 'Payload'],
            'entries': list(map(lambda x: [x['url'], x['payload']], self.vulnerable))
        })

        pass
