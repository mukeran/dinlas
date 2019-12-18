# coding:utf-8

import logging
from urllib import parse
from copy import deepcopy
import random

import requests


class SSTIDetector:
    def __init__(self, results, reports, **kwargs):
        self.results = results
        self.reports = reports
        self.args = kwargs
        self.vulnerable = []

    @staticmethod
    def meta():
        return {
            'name': 'Server-Side Template Injector for all',
            'version': '1.0'
        }

    @staticmethod
    def set_payload():
        randint1 = random.randint(32768, 65536)
        randint2 = random.randint(16384, 32768)

        _sum = randint1 + randint2

        _payload = '{{' + str(randint1) + '+' + str(randint2) + '}}'
        check_str = str(_sum)
        return {'payload': _payload, 'check_str': check_str}

    def exec(self):
        headers = {
            'User_Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.'
                          '2924.87 Safari/537.36'
        }
        for url in self.results['urls']:
            logging.critical('SSTI testing on {}'.format(url))
            attack_url = []
            if url[0:4] != 'http':
                url = 'http://' + url
            parse_result = parse.urlparse(url)
            query = parse.parse_qs(parse_result.query)

            split_dir = parse_result.path.split('/')
            _url = parse_result.scheme + '://' + parse_result.netloc

            for i in range(1, len(split_dir)):
                payload = self.set_payload()
                split = deepcopy(split_dir)
                split[i] = payload['payload']
                check_url = _url + '/'.join(split)
                attack_url.append({'url': check_url, 'payload': payload})

            _url += parse_result.path + '?'

            for key in query.keys():
                payload = self.set_payload()
                tmp = deepcopy(query)
                tmp[key][0] = payload['payload']
                _query = []
                for _key, _value in tmp.items():
                    _query += list(map(lambda x: '{}={}'.format(_key, x), _value))
                attack_url.append({'url': _url + '&'.join(_query), 'payload': payload})

            for test_url in attack_url:
                req = requests.get(test_url['url'], headers=headers)
                if req.text.find(test_url['payload']['check_str']) != -1:
                    logging.critical('SSTI detected: vulnerable url: {}'.format(test_url['url']))
                    self.vulnerable.append({
                        'url': test_url['url'],
                        'payload': test_url['payload']['payload']
                    })

        self.reports.append({
            'title': 'Server Side Template Injection Points',
            'overview': 'Found {} SSTI point(s)'.format(len(self.vulnerable)),
            'header': ['Path', 'Payload'],
            'entries': list(map(lambda x: [x['url'], x['payload']], self.vulnerable))
        })
        logging.info("SSTI scan finished!")
