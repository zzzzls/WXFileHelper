import os
import json
import requests
from requests.exceptions import Timeout

from retry.api import retry_call

import time
import re
import random

from io import BytesIO
from PIL import Image


class Utils:
    def __init__(self):
        self.headers = {
            "accept": "*/*",
            "accept-language": "zh,zh-CN;q=0.9,en;q=0.8",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "sec-ch-ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"macOS\"",
            "sec-fetch-dest": "script",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-site": "same-site",
            "sec-gpc": "1",
            "referrer": "https://szfilehelper.weixin.qq.com/",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        }
        self.session = self.__bind_request_session()

    def __bind_request_session(self):
        session = requests.session()
        session.headers = self.headers
        return session

    def generator_device_id(self):
        """
        绑定设备ID
        """
        return str(random.random())[2:17]

    def fetch(self, url, method="get", params=None, data=None, json=None, timeout=10):
        resp = self.session.request(
            # method, url, params=params, data=data, json=json, timeout=timeout, allow_redirects=False, verify=False, proxies={'https': 'http://127.0.0.1:8888'})
            method, url, params=params, data=data, json=json, timeout=timeout, allow_redirects=False)
        if resp and resp.status_code == requests.codes.ok:
            return resp
        else:
            raise Exception(f"HTTPRequest failed: [{resp.status}] {url}")

    def match(self, pattern, content):
        """
        正则匹配
        """
        res = re.search(pattern, content)
        if res:
            return res.group(1)
        else:
            raise Exception("REMatch failed: {content}")


class WXFilehelper:
    def __init__(self):
        self.host = "https://szfilehelper.weixin.qq.com"
        self.util = Utils()

        if self.wait_login():
            while True:
                has_msg = self.sync_check()
                if has_msg:
                    self.receive_msg()
                time.sleep(0.3)

    def wait_login(self):
        uuid = self.__generator_QRLogin_uuid()
        self.__generator_QR_code(uuid)
        print("\rScan Code, pls ...", end='')
        config = retry_call(self.check_login_status, fkwargs={
            "uuid": uuid}, exceptions=(ValueError, Timeout), tries=50, delay=0.5)

        self.uin = config["uin"]
        self.sid = config["sid"]
        self.skey = config["skey"]
        self.pass_ticket = config["pass_ticket"]

        status = self.__webwx_init()
        return status

    def __generator_QRLogin_uuid(self):
        """
        生成 QRLogin uuid
        """
        params = {
            "appid": "wx_webfilehelper",
            "redirect_uri": "https%3A%2F%2Fszfilehelper.weixin.qq.com%2Fcgi-bin%2Fmmwebwx-bin%2Fwebwxnewloginpage",
            "fun": "new",
            "lang": "zh_CN",
            "_": int(time.time()*1000)
        }

        url = 'https://login.wx.qq.com/jslogin'
        resp = self.util.fetch(url, params=params)
        if resp:
            uuid = self.util.match(
                r'window.QRLogin.uuid = "(.*?)";', resp.text)
            return uuid

    def __generator_QR_code(self, uuid):
        """
        生成 登录二维码
        """
        resp = self.util.fetch(f'https://login.weixin.qq.com/qrcode/{uuid}')
        if resp:
            image = Image.open(BytesIO(resp.content))
            image.show()

    def check_login_status(self, uuid):
        """
        检测登录状态
        """
        params = {
            "loginicon": "true",
            "uuid": uuid,
            "tip": "1",
            "_": int(time.time()*1000),
            "appid": "wx_webfilehelper"
        }
        try:
            resp = self.util.session.get(
                # "https://login.wx.qq.com/cgi-bin/mmwebwx-bin/login", params=params, timeout=20, proxies={'https': 'http://127.0.0.1:8888'})
                "https://login.wx.qq.com/cgi-bin/mmwebwx-bin/login", params=params, timeout=20)
        except Timeout:
            raise Timeout("HTTPRequest timeout")

        wcode = self.util.match(r'window.code=(.*?);', resp.text)

        if wcode == '408':
            print("\rScan Code, pls ...", end='')
            raise ValueError("Scan Code")
        elif wcode == '201':
            print("\rPress OK, pls ...", end='')
            raise ValueError("Press OK")
        elif wcode == '200':
            print("\rLogin success, Welcome~", end='')

            redirect_url = self.util.match(
                r'window.redirect_uri="(.*?)"', resp.text)
            redirect_url = "?fun=new&version=v2&".join(redirect_url.split('?'))

            return self.__webwx_newloginpage(redirect_url)

    def __webwx_newloginpage(self, url):
        """
        获取登录信息
        """
        resp = self.util.fetch(url)
        if resp:
            skey = re.search(r'<skey>(.*?)</skey>', resp.text).group(1)
            wxsid = re.search(r'<wxsid>(.*?)</wxsid>', resp.text).group(1)
            wxuin = re.search(r'<wxuin>(.*?)</wxuin>', resp.text).group(1)
            pass_ticket = re.search(
                r'<pass_ticket>(.*?)</pass_ticket>', resp.text).group(1)
            return {
                "skey": skey,
                "sid": wxsid,
                "uin": wxuin,
                "pass_ticket": pass_ticket
            }

    def __webwx_init(self):
        """
        初始化网页文件传输助手
        """
        params = {
            "lang": "zh_CN",
            "pass_ticket": self.pass_ticket
        }
        data = {"BaseRequest": {"Uin": self.uin, "Sid": self.sid,
                                "Skey": self.skey, "DeviceID": self.util.generator_device_id()}}

        self.util.session.headers.update({"mmweb_appid": "wx_webfilehelper"})

        resp = self.util.fetch('https://szfilehelper.weixin.qq.com/cgi-bin/mmwebwx-bin/webwxinit',
                               method='post', params=params, json=data)
        if resp:
            data = resp.json()
            if data['BaseResponse']['Ret'] == 0:
                nickname = data['User']['NickName']
                print(f"\rLogin success, Welcome [{nickname}]~", end='\n\n')
                self.username = data['User']['UserName']
                self.sync_key = data['SyncKey']
                return True
            else:
                raise ValueError("Webwxinit failed")

    def send_msg(self, msg_content):
        """
        发送消息
        """
        url = f"{self.host}/cgi-bin/mmwebwx-bin/webwxsendmsg"
        params = {
            "lang": "zh_CN",
            "pass_ticket": self.pass_ticket
        }
        msg_id = str(time.time()).replace('.', '') + str(random.randint(0, 9))
        # 解决中文乱码问题
        json_data = json.dumps({"BaseRequest": {"Uin": self.uin, "Sid": self.sid, "Skey": self.skey, "DeviceID": self.util.generator_device_id()},
                                "Msg": {
            "ClientMsgId": msg_id,
            "FromUserName": self.username,
            "LocalID": msg_id,
            "ToUserName": "filehelper",
            "Content": msg_content,
            "Type": 1},
            "Scene": 0}, ensure_ascii=False).encode('utf-8')
        self.util.session.headers.update({"Content-Type": "application/json"})
        resp = self.util.fetch(
            url, method="post", params=params, data=json_data)
        if resp:
            data = resp.json()
            if data['BaseResponse']['Ret'] == 0:
                return True
            else:
                raise ValueError("Send msg failed")

    def sync_check(self):
        """
        监听消息
        """
        url = 'https://szfilehelper.weixin.qq.com/cgi-bin/mmwebwx-bin/synccheck'
        params = {
            'r': int(time.time()*1000),
            'skey': self.skey,
            'sid': self.sid,
            'uin': self.uin,
            'deviceid': self.util.generator_device_id(),
            'synckey': "|".join([f"{key}_{value}" for key, value in self.sync_key['List']]),
            'mmweb_appid': 'wx_webfilehelper'
        }
        self.util.session.headers.update({"mmweb_appid": "wx_webfilehelper"})
        resp = self.util.fetch(url, params=params)
        if resp:
            retcode = self.util.match(
                r'retcode:"(.*?)"', resp.text)
            selector = self.util.match(
                r'selector:"(.*?)"', resp.text)
            if retcode and selector:
                if str(retcode) == '0' and str(selector) != '0':
                    return True
                else:
                    return False

    def receive_msg(self):
        """
        接收消息
        """
        url = "https://szfilehelper.weixin.qq.com/cgi-bin/mmwebwx-bin/webwxsync"
        params = {'sid': self.sid, 'skey': self.skey,
                  'pass_ticket': self.pass_ticket}
        json_data = {"BaseRequest": {"Uin": self.uin, "Sid": self.sid, "Skey": self.skey, "DeviceID": self.util.generator_device_id()},
                     "SyncKey": self.sync_key, "rr": -9822109}

        resp = self.util.fetch(
            url, method="post", params=params, json=json_data)
        if resp:
            # 直接调用 resp.json() 中文消息出现乱码
            data = json.loads(resp.content.decode('utf-8'))
            if data['BaseResponse']['Ret'] == 0:
                if data['AddMsgList']:
                    for msg in data['AddMsgList']:
                        if msg['MsgType'] == 1:
                            # 文本消息
                            print(msg['Content'])
                            self.send_msg(msg['Content'])
                    self.sync_key = data['SyncKey']
            else:
                raise ValueError("Webwxsync failed")


filehelper = WXFilehelper()
