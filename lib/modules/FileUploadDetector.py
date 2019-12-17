# coding:utf-8

import logging
import os
import re
import tempfile

import requests
from urllib.parse import urlparse
from http.cookies import SimpleCookie

from .CSRFDetector import craft_fields
from ..core.Dictionary import read_payload


def file_inputs(form):
    input_name = []
    for input_ in form['fields'].values():
        if input_['type'] == 'file':
            input_name.append(input_['name'])
    return input_name


class FileUploadDetector:
    def __init__(self, results, reports, **kwargs):
        php_info_regex = "\\<title\\>phpinfo\\(\\)\\<\\/title\\>(.|\n)*\\<h2\\>PHP License\\<\\/h2\\>"
        self.payloads = {'php': [
            {
                "description": "Basic php file (plain text) with simple call to phpinfo().",
                "filename": "phpinfo.php",
                "nastyExt": "php",
                "exec_regex": php_info_regex,
                "exts": ["php1", "php2", "php3", "php4", "php5", "phtml", "pht", "Php", "PhP",
                         "pHp", "pHp1", "pHP2", "pHtMl", "PHp5"]
            }, {
                "description": "Valid GIF file with basic call to phpinfo() in the comments section of the file",
                "filename": "phpinfo.gif",
                "nastyExt": "php",
                "exec_regex": php_info_regex,
                "exts": ["php1", "php2", "php3", "php4", "php5", "phtml", "pht", "Php", "PhP",
                         "pHp", "pHp1", "pHP2", "pHtMl", "PHp5"]
            }, {
                "description": "Valid JPG file with basic call to phpinfo() in the comments section of the file",
                "filename": "phpinfo.jpg",
                "nastyExt": "php",
                "exec_regex": php_info_regex,
                "exts": ["php1", "php2", "php3", "php4", "php5", "phtml", "pht", "Php", "PhP",
                         "pHp", "pHp1", "pHP2", "pHtMl", "PHp5"]
            }], 'jsp': [
            {
                "description": "Basic jsp file with simple mathematical expression.",
                "filename": "basic.jsp",
                "nastyExt": "jsp",
                "exec_regex": "12",
                "exts": ["JSP", "jSp"]
            }
        ]}
        self.mime_types = \
            {'rtf': 'application/rtf', 'text': 'text/plain', 'htm': 'text/html', 'jpe': 'image/jpeg',
             'jpg': 'image/jpeg', 'avi': 'video/x-msvideo', 'txt': 'text/plain', 'shtml': 'text/html',
             'ico': 'image/vnd.microsoft.icon', 'zip': 'application/zip', 'py': 'text/x-python', 'gif': 'image/gif',
             'html': 'text/html', 'wav': 'audio/x-wav', 'pl': 'text/x-perl', 'pm': 'text/x-perl',
             'phtml': 'application/x-httpd-php', 'asp': 'text/asp', 'bmp': 'image/x-ms-bmp', 'jpeg': 'image/jpeg',
             '%': 'application/x-trash', 'php': 'application/x-httpd-php', 'png': 'image/png',
             'pht': 'application/x-httpd-php', 'c': 'text/x-csrc', 'java': 'text/x-java', 'sh': 'text/x-sh',
             'css': 'text/css', 'pdf': 'application/pdf', 'mp3': 'audio/mpeg', 'bak': 'application/x-trash',
             '~': 'application/x-trash', 'jsp': 'text/xml'}
        self.file_heads = \
            {'jpg': b'\xff\xd8\xff\xe0\x00', 'png': b'\x89\x50\x4e\x47\x0d\x0a', 'zip': b'\x50\x4b\x03'}
        self.techniques = ['.nasty_ext', '.nasty_ext.valid_ext', '.valid_ext.nasty_ext',
                           '.valid_ext\x00.nasty_ext', '.nasty_ext\x00.valid_ext']
        report = {'title': 'File Upload Detector',
                  'overview': "A Unrestricted File Upload is an attack that is similar to a Code Evaluation "
                              "via Local File Inclusion (PHP) that high-level severity.",
                  'entries': [], 'header': ['URL', 'Name in Form', 'Filename and mime', 'Description']}
        self.results = results
        self.reports = reports
        self._report = report  # unfinished report
        self._session = requests.session()
        self.detect_file_size = 64

        # need to import from user
        self.valid_exts = []  # expose?
        self.success_regex = kwargs.get('success_regex', 'succes')
        self.upload_path = kwargs.get('upload_path', 'http://localhost/hackable/uploads/')

        self.args = kwargs
        if 'cookie' in self.args and self.args['cookie']:
            self.cookie = SimpleCookie()
            self.cookie.load(self.args['cookie'])
            self.cookie = {key: val for key, val in self.cookie.items()}
            for key in self.cookie:
                self._session.cookies.set(*[key, self.cookie[key]])

    @staticmethod
    def meta():
        return {
            'name': 'File Upload Vulnerability Detector for all',
            'version': '1.0'
        }

    def report(self, url, input_name, mime, filename, payload):
        # ['URL', 'Name in Form', 'Filename and mime', 'Description']
        names = '{} {}'.format(filename, mime)
        entry = [url, input_name, names, payload['description']]

        self._report['entries'].append(entry)

    def craft_request(self, url, input_name, post_data, mime, filename, payload):
        """
        try to make request with suffix, mime, filename
        """

        with tempfile.TemporaryFile() as fd:
            fd.write(payload)
            fd.flush()
            fd.seek(0)

            response = self._session.post(url, files={input_name: (filename, fd, mime)},
                                          data=post_data)
            logging.debug('sent file, name: {}, mime: {}'.format(filename, mime))
        return response

    def exec(self):
        # logging.basicConfig(level=logging.DEBUG)
        # detect jsp or php.
        logging.debug(self.results)
        show_php = 0
        show_jsp = 0
        for form in self.results['requests'].values():
            for url_ in [form['url'], form['location']]:
                path = urlparse(url_).path.lower()
                if path.endswith('.php'):
                    show_php += 1
                elif path.endswith('.jsp'):
                    show_jsp += 1

        if (show_jsp != 0) and (show_php != 0):
            logging.critical('both php({}) and jsp({}) detected!...'.format(show_php, show_jsp))
            show_php = 0
            show_jsp = 0
        elif show_php > 0:
            logging.info('php detected {} times!'.format(show_php))
        elif show_jsp > 0:
            logging.info('jsp detected {} times!'.format(show_jsp))

        for form in self.results['requests'].values():
            input_name = file_inputs(form)
            if len(input_name) != 1:
                if len(input_name) > 1:
                    logging.warning('skip multiple file inputs found at {}'.format(form['url']))
                continue
            input_name = input_name[0]

            post_data = craft_fields(form['fields'])

            if form['method'] == 'GET':
                logging.warning('file input with GET method found at {}'.format(form['url']))
                continue

            if not form['content-type'].startswith('multipart'):
                logging.warning('file input with enctype {} found at {}'.format(form['content-type'], form['url']))

            logging.debug('testing {}'.format(form['url']))

            # detect valid extention
            for ext_ in self.mime_types:
                filename = 'tmp.{}'.format(ext_)
                if ext_ in self.file_heads:
                    content = self.file_heads[ext_] + os.urandom(self.detect_file_size)
                else:
                    content = os.urandom(self.detect_file_size)
                res = self.craft_request(form['url'], input_name, post_data,
                                         self.mime_types[ext_], filename, content)
                r = self.upload_success(res.text)
                if r:
                    self.valid_exts.append(ext_)
                    logging.debug('ext {} allowed'.format(ext_))
            # try file upload techniques
            # for php ext, try send different ext variant with different mime
            # for every valid and nasty mime, for every ext, for every ext technique(%00.) and test code exec
            try:
                for lang in self.payloads:
                    if (lang == 'php') and show_jsp > 0:
                        continue
                    if (lang == 'jsp') and show_php > 0:
                        continue
                    for payload in self.payloads[lang]:
                        nasty_mime = self.mime_types[lang]
                        for valid_ext in self.valid_exts:
                            valid_mime = self.mime_types[valid_ext]
                            for tech in self.techniques:
                                for nasty_ext in ([lang] + payload['exts']):
                                    for mime in [valid_mime, nasty_mime]:
                                        ext = tech.replace('nasty_ext', nasty_ext).replace('valid_ext', valid_ext)
                                        filename = payload['filename']
                                        payload_content = read_payload(self.args['root'], filename)
                                        filename = filename.split('.')[0] + ext
                                        res = self.craft_request(form['url'], input_name, post_data,
                                                                 mime, filename, payload_content)
                                        match = self.upload_success(res.text)
                                        if not match:
                                            continue
                                        logging.info('uploaded {} successfully with mime {}'.format([filename], mime))
                                        url = [self.upload_path + filename if self.upload_path.endswith('/')
                                               else self.upload_path + '/' + filename]
                                        if '\x00' in filename:
                                            url.append('\x00'.join(url[-1].split('\x00')[:-1]))
                                        for u in url:
                                            if self.code_exec(u, payload['exec_regex']):
                                                logging.critical('code exec detected !')
                                                self.report(form['url'], input_name, mime, filename, payload)
                                                raise Exception("out")
            except Exception as e:
                pass

        self._report['overview'] = 'Found {} File Upload vulnerability. <br>'.format(len(self._report['entries'])) + \
                                   self._report['overview']
        self.reports.append(self._report)
        logging.info("File Upload Tasks finished !")

    def upload_success(self, html):
        if self.success_regex:
            uploaded = re.search(self.success_regex, html)
            logging.warning('upload regex: {}'.format(uploaded))
            return uploaded

    def code_exec(self, u, regex):

        res = self._session.get(u)

        r = re.search(regex, res.text)
        logging.warning('detecting code exec {}, {}'.format(u, r))
        return bool(r)
