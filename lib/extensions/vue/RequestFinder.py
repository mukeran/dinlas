# coding:utf-8

from selenium import webdriver


class RequestFinder:
    def __init__(self, **kwargs):
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'RequestFinder for Vue',
            'version': '1.0'
        }

    def exec(self):
        chrome_options = webdriver.ChromeOptions()
        if self.args.__contains__('headless'):
            chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(chrome_options=chrome_options)
        driver.get(self.args['url'])
        links = list(map(lambda x: x.get_property('href'), driver.find_elements_by_tag_name('a')))
        print(links)
