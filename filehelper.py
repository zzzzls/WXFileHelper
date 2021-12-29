import os
import json
import threading

import pathlib

import hashlib
import requests
from requests.exceptions import Timeout
from requests_toolbelt import MultipartEncoder

from retry.api import retry_call

import time
import re
import random

from io import BytesIO
from PIL import Image

# 取消 SSL 警告
requests.packages.urllib3.disable_warnings()


WX_LOGIN_HOST = "https://login.wx.qq.com"
WX_FILEHELPER_HOST = "https://szfilehelper.weixin.qq.com"
WX_FILEUPLOAD_HOST = "https://file.wx2.qq.com"


class Message:
    """
    消息类
    """
    _lock = threading.Lock()
    _instance = None

    def __new__(cls, *args, **kwargs):
        """单例"""
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        self.uin = None
        self.sid = None
        self.skey = None
        self.pass_ticket = None
        self.webwx_data_ticket = None

        # 消息列表
        self.sync_key = None

        self.username = None
        self.username_hash = None

        self.wx_req = WXRequest()

    def generate_message_id(self):
        """生成消息 id"""
        return str(time.time()).replace('.', '')+str(random.randint(0, 9))

    def generate_base_request(self):
        """生成 BaseRequest"""
        return {
            "Uin": self.uin,
            "Sid": self.sid,
            "Skey": self.skey,
            "DeviceID": Utils.generate_device_id()
        }

    def generate_upload_media_request(self, file_size, file_md5):
        """生成 UploadMediaRequest"""
        return {
            "UploadType": 2,
            "BaseRequest": self.generate_base_request(),
            "ClientMediaId": self.generate_message_id(),
            "TotalLen": file_size,
            "StartPos": 0,
            "DataLen": file_size,
            "MediaType": 4,
            "FromUserName": self.username_hash,
            "ToUserName": "filehelper",
            "FileMd5": file_md5
        }

    def wx_upload_file(self, file_path):
        """上传文件"""

        url = f"{WX_FILEUPLOAD_HOST}/cgi-bin/mmwebwx-bin/webwxuploadmedia"
        file_obj = Utils.load_image(file_path)

        params = {
            "f": "json",
            "random": Utils.generate_random_key(4)
        }

        data = MultipartEncoder(
            fields={
                "name": file_obj['name'],
                "lastModifiedDate": file_obj['lastModifiedDate'],
                "size": file_obj['size'],
                "type": file_obj['type'],
                "mediatype": "pic",
                "uploadmediarequest": json.dumps(self.generate_upload_media_request(file_obj['size'], file_obj['md5'])),
                "webwx_data_ticket": self.webwx_data_ticket,
                "pass_ticket": self.pass_ticket,
                "filename": (file_obj['name'], file_obj['content'], file_obj['type'])
            })

        self.wx_req.update_headers({"Content-Type": data.content_type})
        resp = self.wx_req.fetch(url, method="post", params=params, data=data)

        if resp:
            resp_json = resp.json()
            if resp_json['BaseResponse']['Ret'] == 0:
                return resp_json['MediaId']

        raise ValueError("Upload file failed")

    def bind_msg_data(self, type_=1, content="", media_id=""):
        """
        构建消息参数

        :param type_: 消息类型
            type_ = 1: 文本消息
            type_ = 3: 图片消息

        :param content: 文本消息
        :param media_id: 媒体消息
        """

        msg_id = self.generate_message_id()
        # 解决中文乱码问题
        msg_data = json.dumps({
            "BaseRequest": self.generate_base_request(),
            "Msg": {
                "ClientMsgId": msg_id,
                "FromUserName": self.username_hash,
                "LocalID": msg_id,
                "ToUserName": "filehelper",
                "Content": content,
                "Type": type_,
                "MediaId": media_id
            },
            "Scene": 0
        }, ensure_ascii=False).encode("utf-8")
        return msg_data

    def send_msg(self, content=None, file_path=None):
        """发送消息"""

        if content:
            url = f"{WX_FILEHELPER_HOST}/cgi-bin/mmwebwx-bin/webwxsendmsg"

            params = {
                "lang": "zh_CN",
                "pass_ticket": self.pass_ticket
            }
            data = self.bind_msg_data(type_=1, content=content)
        elif file_path:
            url = f"{WX_FILEHELPER_HOST}/cgi-bin/mmwebwx-bin/webwxsendmsgimg"
            params = {
                "fun": "async",
                "f": "json",
                "pass_ticket": self.pass_ticket
            }

            media_id = self.wx_upload_file(file_path)
            print(media_id)
            data = self.bind_msg_data(type_=3, media_id=media_id)

        self.wx_req.update_headers({"Content-Type": "application/json"})
        resp = self.wx_req.fetch(
            url, method="post", params=params, data=data)
        if resp:
            data = resp.json()
            if data['BaseResponse']['Ret'] == 0:
                return True
            else:
                raise ValueError("Send msg failed")

    def sync_msg_check(self):
        """
        监听消息
        """
        url = f'{WX_FILEHELPER_HOST}/cgi-bin/mmwebwx-bin/synccheck'
        params = {
            'r': int(time.time()*1000),
            'skey': self.skey,
            'sid': self.sid,
            'uin': self.uin,
            'deviceid': Utils.generate_device_id(),
            'synckey': "|".join([f"{key}_{value}" for key, value in self.sync_key['List']]),
            'mmweb_appid': 'wx_webfilehelper'
        }
        self.wx_req.update_headers({"mmweb_appid": "wx_webfilehelper"})
        resp = self.wx_req.fetch(url, params=params)
        if resp:
            retcode = Utils.match(
                r'retcode:"(.*?)"', resp.text)
            selector = Utils.match(
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
        url = f"{WX_FILEHELPER_HOST}/cgi-bin/mmwebwx-bin/webwxsync"
        params = {'sid': self.sid, 'skey': self.skey,
                  'pass_ticket': self.pass_ticket}
        json_data = {"BaseRequest": self.generate_base_request(),
                     "SyncKey": self.sync_key}

        resp = self.wx_req.fetch(
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
                    self.sync_key = data['SyncKey']
            else:
                raise ValueError("Webwxsync failed")

    def wait_msg(self):
        """监听消息"""
        while True:
            has_msg = self.sync_msg_check()
            if has_msg:
                self.receive_msg()
            time.sleep(0.3)

    def __str__(self):
        return f"""uin: {self.uin}
            sid: {self.sid}
            skey: {self.skey}
            pass_ticket: {self.pass_ticket}
            webwx_data_ticket: {self.webwx_data_ticket}
            sync_key: {self.sync_key}
            username: {self.username}
            username_hash: {self.username_hash}"""


class Utils:
    @staticmethod
    def match(pattern, content):
        """正则匹配"""
        res = re.search(pattern, content)
        if res:
            return res.group(1)
        else:
            raise Exception("REMatch failed: {content}")

    @staticmethod
    def generate_device_id():
        """生成设备ID"""
        return str(random.random())[2:17]

    @staticmethod
    def generate_random_key(length=4):
        lst = list(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        random.shuffle(lst)
        return "".join(lst[:length])

    @staticmethod
    def load_image(image_path):
        """加载图片信息"""
        file_obj = pathlib.Path(image_path)
        file_stat = file_obj.stat()

        file_content = file_obj.read_bytes()
        file_type = f"image/{file_obj.suffix[1:].lower()}"
        file_size = file_stat.st_size
        file_last_modified_date = time.strftime(
            '%a %b %d %Y %H:%M:%S GMT+0800 (中国标准时间)', time.localtime(file_stat.st_mtime))
        file_md5 = Utils.gen_md5(file_content)

        return {
            "name": file_obj.name,
            "size": str(file_size),
            "lastModifiedDate": file_last_modified_date,
            "type": file_type,
            "md5": file_md5,
            "content": file_content
        }

    @staticmethod
    def gen_md5(obj):
        """计算 md5"""
        md5 = hashlib.md5()
        md5.update(obj)
        return md5.hexdigest()


class WXRequest:
    """web 请求类"""
    _lock = threading.Lock()
    _instance = None

    def __new__(cls, *args, **kwargs):
        """单例"""
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, headers=None):
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
            "referrer": WX_FILEHELPER_HOST,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        } or headers
        self.session = self.__bind_request_session()

    def __bind_request_session(self):
        session = requests.session()
        session.headers = self.headers
        return session

    def fetch(self, url, method="get", params=None, data=None, json=None, timeout=10):
        resp = self.session.request(
            method, url, params=params, data=data, json=json, timeout=timeout, allow_redirects=False, verify=False, proxies={'https': 'http://127.0.0.1:8888'})
        # method, url, params=params, data=data, json=json, timeout=timeout, allow_redirects=False)
        if resp and resp.status_code == requests.codes.ok:
            return resp
        else:
            raise Exception(f"HTTPRequest failed: [{resp.status}] {url}")

    def update_headers(self, headers):
        """临时添加自定义 headers"""
        self.headers.update(headers)


class WXFilehelper:
    def __init__(self):
        self.wx_req = WXRequest()
        self.message = Message()

        if self.wait_login():
            self.message.wait_msg()

        # self.message.send_msg("你好")
        # self.message.send_msg(file_path="/Users/zzzzls/Desktop/desk.png")

    def wait_login(self):
        uuid = self.__generate_QRLogin_uuid()
        self.__generate_QR_code(uuid)
        print("\rScan Code, pls ...", end='')
        config = retry_call(self.__check_login_status, fkwargs={
            "uuid": uuid}, exceptions=(ValueError, Timeout), tries=50, delay=0.5)

        self.message.uin = config['uin']
        self.message.sid = config['sid']
        self.message.skey = config['skey']
        self.message.pass_ticket = config['pass_ticket']

        status = self.__webwx_init()
        return status

    def __generate_QRLogin_uuid(self):
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

        url = f'{WX_LOGIN_HOST}/jslogin'
        resp = self.wx_req.fetch(url, params=params)
        if resp:
            uuid = Utils.match(
                r'window.QRLogin.uuid = "(.*?)";', resp.text)
            return uuid

    def __generate_QR_code(self, uuid):
        """
        生成 登录二维码
        """
        resp = self.wx_req.fetch(f'{WX_LOGIN_HOST}/qrcode/{uuid}')
        if resp:
            image = Image.open(BytesIO(resp.content))
            image.show()

    def __check_login_status(self, uuid):
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
            resp = self.wx_req.fetch(
                f"{WX_LOGIN_HOST}/cgi-bin/mmwebwx-bin/login", params=params, timeout=20)
        except Timeout:
            raise Timeout("HTTPRequest timeout")

        wcode = Utils.match(r'window.code=(.*?);', resp.text)

        if wcode == '408':
            print("\rScan Code, pls ...", end='')
            raise ValueError("Scan Code")
        elif wcode == '201':
            print("\rPress OK, pls ...", end='')
            raise ValueError("Press OK")
        elif wcode == '200':
            print("\rLogin success, Welcome~", end='')

            redirect_url = Utils.match(
                r'window.redirect_uri="(.*?)"', resp.text)
            redirect_url = "?fun=new&version=v2&".join(redirect_url.split('?'))

            return self.__webwx_newloginpage(redirect_url)

    def __webwx_newloginpage(self, url):
        """
        获取登录信息
        """
        resp = self.wx_req.fetch(url)
        if resp:
            skey = Utils.match(r'<skey>(.*?)</skey>', resp.text)
            wxsid = Utils.match(r'<wxsid>(.*?)</wxsid>', resp.text)
            wxuin = Utils.match(r'<wxuin>(.*?)</wxuin>', resp.text)
            pass_ticket = Utils.match(
                r'<pass_ticket>(.*?)</pass_ticket>', resp.text)
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
            "pass_ticket": self.message.pass_ticket
        }
        data = {"BaseRequest": self.message.generate_base_request()}

        self.wx_req.update_headers({"mmweb_appid": "wx_webfilehelper"})

        resp = self.wx_req.fetch(f'{WX_FILEHELPER_HOST}/cgi-bin/mmwebwx-bin/webwxinit',
                                 method='post', params=params, json=data)
        if resp:
            data = resp.json()
            if data['BaseResponse']['Ret'] == 0:

                self.message.username = data['User']['NickName']
                self.message.username_hash = data['User']['UserName']
                self.message.sync_key = data['SyncKey']
                self.message.webwx_data_ticket = self.wx_req.session.cookies.get(
                    "webwx_data_ticket")

                print(
                    f"\rLogin success, Welcome [{self.message.username}]~", end='\n\n')

                return True
            else:
                raise ValueError("Webwxinit failed")


filehelper = WXFilehelper()
