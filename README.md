# WXFileHelper
微信网页文件传输助手 Python 实现



已知 bug：

- 2022-04-24：发送大文件超时
- 2022-05-12：部分账号登录可能会遇到：ValueError: Webwxinit failed，临时解决方案：
   ```python
    # 更换 HOST，filehelper.py 26 行
    # WX_FILEHELPER_HOST = "https://szfilehelper.weixin.qq.com"
    WX_FILEHELPER_HOST = "https://filehelper.weixin.qq.com"
   ```
