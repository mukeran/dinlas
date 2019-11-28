# coding:utf-8
# Please notice that this module is not finished!!!

from queue import SimpleQueue
from hashlib import sha256

from selenium import webdriver
from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException
from browsermobproxy import Server


class DynamicRequestFinder:
    def __init__(self, results, **kwargs):
        self.results = results
        self.args = kwargs
        # Create proxy server
        self.proxy_server = Server(self.args['browsermobproxy'])
        self.proxy_server.start()
        self.proxy = self.proxy_server.create_proxy()
        # Create Chrome engine
        self.chrome_options = webdriver.ChromeOptions()
        self.chrome_options.add_argument('--proxy-server={}'.format(self.proxy.proxy))
        if self.args.__contains__('headless'):
            self.chrome_options.add_argument('--headless')
        self.chrome_options.add_argument('--disable-gpu')
        self.driver = webdriver.Chrome(chrome_options=self.chrome_options)
        # Declare attributes
        self.pages = []
        self.same_pages = []
        self.requests = []

    def __del__(self):
        self.proxy_server.stop()
        self.driver.quit()

    @staticmethod
    def meta():
        return {
            'name': 'RequestFinder for dynamic websites',
            'version': '1.0'
        }

    def get_pages(self):
        self.pages.append(self.args['url'])
        queue = SimpleQueue()
        queue.put_nowait(self.args['url'])
        hashes = []

        while not queue.empty():
            url = queue.get_nowait()
            self.driver.get(url)
            h = sha256(self.driver.page_source.encode('utf-8')).hexdigest()
            if h in hashes:
                continue
            hashes.append(h)
            links = self.driver.find_elements_by_tag_name('a')
            for link in links:
                href = str(link.get_attribute('href'))
                if href not in self.pages and href is not None and href.startswith(self.args['url']):
                    self.pages.append(href)
                    queue.put_nowait(href)
            visited = [sha256(self.driver.get_screenshot_as_base64().encode('utf-8')).hexdigest()]

            def check_buttons(current_url, buttons, depth):
                if depth >= 5 or len(visited) >= 100:
                    return
                for i in range(0, len(buttons)):
                    button = buttons[i]
                    try:
                        button.click()
                    except ElementClickInterceptedException:
                        continue
                    except ElementNotInteractableException:
                        continue
                    if self.driver.current_url != current_url:
                        if self.driver.current_url not in self.pages \
                                and self.driver.current_url.startswith(self.args['url']):
                            self.pages.append(self.driver.current_url)
                            queue.put_nowait(self.driver.current_url)
                    else:
                        image = sha256(self.driver.get_screenshot_as_base64().encode('utf-8')).hexdigest()
                        if image not in visited:
                            visited.append(image)
                            check_buttons(current_url, self.driver.find_elements_by_tag_name('button'), depth + 1)
                    self.driver.get(current_url)
                    buttons = self.driver.get(current_url)

            check_buttons(self.driver.current_url, self.driver.find_elements_by_tag_name('button'), 0)
        print(self.pages)

    def get_requests(self):
        self.proxy.new_har('page', options={
            'captureHeaders': True,
            'captureContent': True
        })

    @staticmethod
    def fill_page(_input, _textarea):
        pass

    @staticmethod
    def record_result(har):
        for entry in har['log']['entries']:
            headers = dict(zip([x['name'].lower() for x in entry['request']['headers']],
                               [x['value'] for x in entry['request']['headers']]))
            if headers['content-type'] == 'application/www-form-urlencoded':
                pass
            elif headers['content-type'] == 'application/json':
                pass
            elif headers['content-type'] == 'application/xml':
                pass
            elif headers['content-type'] == 'application/javascript':
                pass
            elif headers['content-type'] == 'application/form-data':
                pass
            else:
                continue

    def exec(self):
        self.get_pages()
        self.get_requests()
