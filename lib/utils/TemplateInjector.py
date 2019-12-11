# coding:utf-8

from urllib.parse import urljoin

import requests


class TemplateInjector:
    def __init__(self, results, reports, **kwargs):
        self.results = results
        self.reports = reports
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Template Injector for all',
            'version': '1.0'
        }

    def exec(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'
        }

        url = urljoin(self.args['url'], '{{ config }}')
        req = requests.get(url, head=headers, timeout=5)
        if req.text.find('<Config') is not -1:
            self.results['url'].append({
                'url': url,
                'count': req.text.count('<Config')
            })

        self.reports.append({
            'title': 'Template injections dir',
            'overview': 'Found {} Injections'.format(len(self.dir)),
            'header': ['url', 'Count'],
            'entries': list(map(self.results['url'], self.results['count']))
        })
        pass
