# coding:utf-8

import os
import time

from jinja2 import Environment, FileSystemLoader

from dinlas import VERSION


class Reporter:
    def __init__(self, reports, **kwargs):
        self.args = kwargs
        self.reports = reports
        self.jinja = Environment(loader=FileSystemLoader(os.path.join(self.args['root'], 'templates')))

    def generate(self):
        generate_time = time.localtime()
        print(self.reports)
        template = self.jinja.get_template('default.jinja2')
        filename = 'report-{}-{}.html'.format(time.strftime('%Y-%m-%d', generate_time),
                                              int(time.time()))
        path = os.path.join(os.getcwd(), filename)
        if 'output' in self.args:
            if os.path.exists(self.args['output']) and os.path.isdir(self.args['output']):
                path = os.path.join(self.args['output'], filename)
            else:
                path = self.args['output']
        with open(path, 'w') as f:
            f.write(template.render(date=time.asctime(), extension=self.args['extension'],
                                    version=VERSION, reports=self.reports))
        print('The report has been generated at {}'.format(path))
