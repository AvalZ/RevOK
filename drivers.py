import asyncio
import time

from abc import abstractmethod, ABC
from selenium import webdriver
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By

from loguru import logger


class Driver(ABC):

    @abstractmethod
    def start_scan(self):
        pass

    @abstractmethod
    def check_for_flag(self, flag):
        pass

    @abstractmethod
    def is_scan_done(self):
        pass


class MetasploitDriver(Driver):

    def __init__(self, baseurl):
        options = webdriver.FirefoxOptions()
        # options.add_argument('-headless')
        self.driver = webdriver.Firefox(options=options)
        self.baseurl = baseurl

    def __del__(self):
        self.driver.close()

    def start_scan(self):
        self.driver.get("{}/login".format(self.baseurl))
        self.driver.set_window_size(640, 1080)
        self.driver.find_element(By.ID, "user_session_username").clear()
        self.driver.find_element(By.ID, "user_session_username").send_keys("avalz")
        self.driver.find_element(By.ID, "user_session_password").clear()
        self.driver.find_element(By.ID, "user_session_password").send_keys("~Nv+=:K26S7CeUzE")
        self.driver.find_element(By.NAME, "commit").click()
        self.driver.find_element(By.LINK_TEXT, "Fuzzer").click()
        self.driver.find_element(By.LINK_TEXT, "Scan...").click()
        self.driver.find_element(By.ID, "scan_task_address_string").click()
        self.driver.find_element(By.ID, "scan_task_address_string").click()
        element = self.driver.find_element(By.ID, "scan_task_address_string")
        actions = ActionChains(self.driver)
        actions.double_click(element).perform()
        self.driver.find_element(By.ID, "scan_task_address_string").click()
        self.driver.find_element(By.ID, "scan_task_address_string").clear()
        self.driver.find_element(By.ID, "scan_task_address_string").send_keys("localhost")
        self.driver.find_element(By.ID, "popup_submit").click()

    def check_for_flag(self, flag):

        self.driver.get("https://localhost:3790/")
        self.driver.set_window_size(640, 1080)
        self.driver.find_element(By.LINK_TEXT, "Fuzzer").click()
        # FIXME: change number of services
        self.driver.find_element(By.LINK_TEXT, "4 services").click()

        print(self.driver.page_source)
        return flag in self.driver.page_source

class MockDriver(Driver):

    def __init__(self, running_file='running'):
        self.running_file = running_file

    def start_scan(self):
        with open(self.running_file, 'w') as f:
            f.write(str(1))

    def check_for_flag(self, flag):
        pass

    def is_scan_done(self):
        with open(self.running_file, 'r') as f:
            running = bool(int(f.read().strip('\n')))
        return not running

    def wait_for_scan_done(self):
        while not md.is_scan_done():
            time.sleep(1)


if __name__ == "__main__":
    md = MockDriver()
    logger.info('Starting scan')
    md.start_scan()
    md.wait_for_scan_done()
    logger.success('Scan done')


    # print(md.check_for_flag("4f6a142e-56ff-f229-4d1d-aa055c000de7"))

