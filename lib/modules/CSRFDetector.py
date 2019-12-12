# coding:utf-8

import logging
from requests_html import HTMLSession
from urllib.parse import urljoin, urlencode
from http.cookies import SimpleCookie


def find_token(form, form2):
    """
    rely on the order of the :hidden selector
    :param form:
    :param form2:
    :return:
    """
    hidden = form.find(':hidden')
    hidden2 = form2.find(':hidden')
    if len(hidden) != len(hidden2):
        logging.error("two requests doesn't have the same hidden inputs")
    for hid, hid2 in zip(hidden, hidden2):
        if 'value' in hid.attrs and 'value' in hid2.attrs and \
                'name' in hid.attrs and 'name' in hid2.attrs:
            if hid.attrs['value'] != hid2.attrs['value']:
                logging.info('CSRF Token Detected: name:{}, before:{}, after:{}'
                             .format(hid.attrs['name'], hid.attrs['value'], hid2.attrs['value']))
                return True
        else:
            logging.debug('hidden input without value or name :{}\n{}'.format(hid.attrs, hid2.attrs))
    return False


def craft_field(form, location):
    url = urljoin(location, form.attrs['action']) if 'action' in form.attrs else location
    fields = {}
    inputs = form.find('input, button')
    # data = {}
    for inp in inputs:
        if 'name' not in inp.attrs:
            continue
        typ = inp.attrs['type'] if 'type' in inp.attrs else 'text'
        name = inp.attrs['name']
        value = inp.attrs['value'] if 'value' in inp.attrs else ''
        required = True if 'required' in inp.attrs else False
        if typ == 'radio':
            if name in fields:
                fields[name]['values'].append(value)
            else:
                fields[name] = {
                    'type': 'radio',
                    'name': name,
                    'required': required,
                    'values': [value]
                }
        elif typ == 'checkbox':
            checked = True if 'checked' in inp.attrs and (inp.attrs['checked'] == 'checked'
                                                          or inp.attrs['checked'] == '') else False
            fields[name] = {
                'type': 'checkbox',
                'name': name,
                'required': required,
                'value': value,
                'checked': checked
            }
        else:
            fields[name] = {
                'type': typ,
                'name': name,
                'required': required,
                'default': value
            }
    textareas = form.find('textarea')
    for textarea in textareas:
        if 'name' not in textarea.attrs:
            continue
        name = textarea.attrs['name']
        fields[name] = {
            'type': 'textarea',
            'name': name,
            'required': True if 'required' in textarea.attrs else False,
            'default': textarea.text
        }
    selects = form.find('select')
    for select in selects:
        if 'name' not in select.attrs:
            continue
        name = select.attrs['name']
        multiple = True if 'multiple' in select.attrs else False
        required = True if 'required' in select.attrs else False
        values = []
        options = select.find('option')
        for option in options:
            if 'value' not in option.attrs:
                continue
            values.append(option.attrs['value'])
        fields[name] = {
            'type': 'select',
            'name': name,
            'multiple': multiple,
            'required': required,
            'values': values
        }
    return craft_fields(fields)


def compare(req1, req2):
    if abs(len(req1.text) - len(req2.text)) < (len(req1.text) * 0.1):
        if req1.status_code == req2.status_code and 200 <= req1.status_code < 300:
            return True
        logging.debug('status code check failed {}\n\n{}'.format(req1.text, req2.text))
    return False


class CSRFDetector:
    def __init__(self, results, reports, **kwargs):
        report = {'title': 'CSRF Detector',
                  'overview': "CSRF vulnerabilities is an attack that forces an end user to execute "
                              "unwanted actions on a web application in which they're currently authenticated."
                              "<br> This Detector can automatic detect CSRF Token "
                              "and try to detect 'Referer' header check."
                              "If any following form is important, please consider adding protect.",
                  'entries': [], 'header': ['URL', 'Method', 'Data', 'Request with referer', 'Request without referer']}
        self.results = results
        self.reports = reports
        self.csrf_report = report
        self._session = HTMLSession()
        self.img_suffix = ['jpg', 'png', 'jpge', 'ico', 'gif', 'bmp']
        self.filter_words = ['跳', '搜', '查', '找', '登陆', '注册', 'search', 'register', 'login', 'log in', 'sign']
        self.action_filters = ['search', 'find', 'login', 'reg', 'logout', 'find'
                               "baidu.com", "google.com", "so.com", "bing.com",
                               "soso.com", "sogou.com"]
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
            'name': 'CSRF Detector for all',
            'version': '1.0'
        }

    def find_recaptcha(self, form):
        """
        find recaptcha by non-typical img suffix
        :param form:
        :return:
        """
        imgs = form.find('img')
        for img in imgs:
            src = img.attrs.get('src', '')
            if src:
                if '?' in src:
                    src = src.split('?')[0]
                suffix = src.split('/')[-1].split('.')[-1]
                logging.debug("img suffix: {}".format(suffix))
                if len(suffix) < 5:
                    if [fil for fil in self.img_suffix if fil in suffix]:  # or ==
                        logging.info("non recaptcha img in form detected: {}".format(img.attrs['src']))
                        return False
                    logging.info("recaptcha detected: {}".format(img.attrs['src']))
                    return True
        return False

    def report(self, url, method, data, req, req_no_ref):
        text = ''.join([str(res.status_code) + '->' for res in req.history]) + str(req.status_code) + ' '
        text += req.text if len(req.text) < 150 else 'data length: {}'.format(len(req.text))
        text_no_ref = ''.join([str(res.status_code) + '->' for res in req_no_ref.history]) \
                      + str(req_no_ref.status_code) + ' '
        text_no_ref += req_no_ref.text if len(req_no_ref.text) < 150 \
            else ' data length: {}'.format(len(req_no_ref.text))
        entry = [url, method, urlencode(data), text, text_no_ref]

        self.csrf_report['entries'].append(entry)

    def exec(self):
        visited = set()
        for form_ in self.results['requests'].values():
            location = form_['location']
            if location in visited:  # 要不要 start with
                continue
            visited.add(location)

            res = self._session.get(location)
            # render ??
            forms = res.html.find('form')
            for form_index, form in enumerate(forms):
                # skip useless form by black list
                action = form.attrs['action'] if 'action' in form.attrs else location
                if [fil for fil in self.action_filters if fil in action.lower()]:
                    logging.debug('keyword in action, skip {}:'.format(form))  # 用一个id表示？
                    continue

                if form.find('input[type="password"]'):
                    continue
                # skip by placeholder filter

                def filter_placeholder(form_to_filter):
                    for ph in form_to_filter.find('[placeholder]'):
                        if [fil for fil in self.filter_words if fil in ph.attrs['placeholder'].lower()]:
                            logging.debug('keyword in placeholder, skip {}'.format(form_to_filter))
                            return True
                    return False

                if filter_placeholder(form):
                    continue
                # skip form without submit button
                if not form.find('input[type="submit"], button[type="submit"]'):  # :submit
                    continue
                # CSRF Token check
                if form.find(':hidden'):
                    res2 = self._session.get(location)
                    form2 = res2.html.find('form')[form_index]
                    if find_token(form, form2):
                        continue

                if form.find('img'):
                    if self.find_recaptcha(form):
                        continue

                # Referer check
                data = craft_field(form, location)
                # if method == 'GET':
                #     location = location.split('?')[0]
                url = urljoin(location, form.attrs['action']) if 'action' in form.attrs else location
                method = form.attrs['method'].upper() if 'method' in form.attrs else 'GET'
                if method == 'GET':
                    req1 = self._session.get(url, headers={'referer': location})
                    req_no_ref = self._session.get(url)
                    req2 = self._session.get(url, headers={'referer': location})
                else:
                    req1 = self._session.request(method, url,
                                                 headers={'referer': location})  # "allow redirect but check"
                    req_no_ref = self._session.request(method, url)
                    req2 = self._session.request(method, url,
                                                 headers={'referer': location})  # ensure referer
                logging.debug('assert no referer: {}'.format(req_no_ref.headers))
                assert 'referer' not in req_no_ref.headers
                if compare(req1, req_no_ref):
                    if not compare(req1, req2):
                        logging.critical('Double check failed: {}\ndata2: {}'.format(req1.text, req2.text))
                        continue
                    logging.critical(
                        'CSRF Detected: text length:{}, without referer: text length:{}'.format(len(req1.text),
                                                                                                len(req_no_ref.text)))
                    self.report(url, method, data, req1, req_no_ref)
                logging.warning(
                    'Referer check detected: text length:{}, without referer: text length:{}'.format(len(req1.text),
                                                                                                     len(req2.text)))

        self.csrf_report['overview'] = 'Found {} possible csrf forms. <br>'.format(len(self.csrf_report['entries'])) + \
                                       self.csrf_report['overview']
        self.reports.append(self.csrf_report)
        logging.info("CSRF scan finished !")


def value(field):
    """
    default values for a form
    :param field
    :return: value
    """
    defaults = {
        "color": "#bcda55",
        "date": "2019-03-03",
        "datetime": "2019-03-03T20:35:34.32",
        "datetime-local": "2019-03-03T22:41",
        "email": "dinlas2019@mailinator.com",
        "file": ["pix.gif", "GIF89a", "image/gif"],
        "hidden": "default",
        "month": "2019-03",
        "number": "1337",
        "password": "Leet3in_",  # 8 characters with uppercase, digit and special char for common rules
        "radio": "beton",
        "range": "37",
        "search": "default",
        "submit": "submit",
        "tel": "0606060606",
        "text": "default",
        "time": "13:37",
        "url": "http://dinlas.com/",
        "week": "2019-W24"
    }
    if 'default' in field and field['default']:
        return field['default']
    if field['type'] == 'text' and 'mail' in field['name']:
        return defaults['email']
    if field['type'] == 'text' and 'pass' in field['name'] or 'pwd' in field['name']:
        return defaults['email']
    if field['type'] in ('select',):
        return field['values'][0] if 'values' in field and len(field['values']) > 0 else 'default'
    if field['type'] in ('checkbox',):
        if field['checked']:
            return field['value'] or 'on'
    if field['type'] in defaults:
        return defaults[field['type']]
    logging.error('Unknown input type {}'.format(field))
    return None


def craft_fields(fields):
    # request = {"url": url, "cookie": "PHPSESSID=muihhepaqno9bn31mhfrgstk00; security=low"}
    logging.debug('fields: {}'.format(fields))
    return {field['name']: value(field) for field in fields.values() if value(field)}
