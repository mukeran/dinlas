# coding:utf-8

from queue import SimpleQueue
from urllib.parse import urljoin

from requests_html import HTMLSession


class StaticRequestFinder:
    def __init__(self, **kwargs):
        self.args = kwargs
        self.requests = []

    @staticmethod
    def meta():
        return {
            'name': 'Request Finder for static websites',
            'version': '1.0'
        }

    def exec(self, results):
        visited = set()
        session = HTMLSession()
        queue = SimpleQueue()
        queue.put_nowait(self.args['url'])
        visited.add(self.args['url'])
        count = 0
        while not queue.empty():
            count += 1
            if count > self.args['max_page_count']:
                break
            url = queue.get_nowait()
            print(url)
            r = session.get(url)
            links = r.html.absolute_links
            for link in links:
                def is_exclude():
                    for exc in self.args['exclude']:
                        if link.startswith(exc):
                            return True
                    return False
                if link.startswith(self.args['url'])\
                        and not is_exclude()\
                        and link not in visited:
                    visited.add(link)
                    queue.put_nowait(link)
            forms = r.html.find('form')
            for form in forms:
                request = {
                    'url': urljoin(r.url, form.attrs['action']) if 'action' in form.attrs else '',
                    'method': form.attrs['method'].upper() if 'method' in form.attrs else 'GET',
                    'content-type': form.attrs['enctype'] if 'enctype' in form.attrs else
                    'application/x-www-form-urlencoded',
                    'fields': {}
                }
                inputs = form.find('input')
                for inp in inputs:
                    if 'name' not in inp.attrs:
                        continue
                    typ = inp.attrs['type'] if 'type' in inp.attrs else 'text'
                    name = inp.attrs['name']
                    value = inp.attrs['value'] if 'value' in inp.attrs else ''
                    required = True if 'required' in inp.attrs else False
                    if typ == 'radio':
                        if name in request['fields']:
                            request['fields'][name]['values'].append(value)
                        else:
                            request['fields'][name] = {
                                'type': 'radio',
                                'name': name,
                                'required': required,
                                'values': [value]
                            }
                    else:
                        request['fields'][name] = {
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
                    request['fields'][name] = {
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
                    request['fields'][name] = {
                        'type': 'select',
                        'name': name,
                        'multiple': multiple,
                        'required': required,
                        'values': values
                    }
                self.requests.append(request)
        results['requests'] = self.requests
