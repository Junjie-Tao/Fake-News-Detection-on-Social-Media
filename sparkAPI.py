# coding: utf-8
import _thread as thread
import os
import time
import base64

import base64
import datetime
import hashlib
import hmac
import json
from urllib.parse import urlparse
import ssl
from datetime import datetime
from time import mktime
from urllib.parse import urlencode
from wsgiref.handlers import format_date_time

import websocket
import openpyxl
from concurrent.futures import ThreadPoolExecutor, as_completed
import os


class Ws_Param(object):
    # 初始化
    def __init__(self, APPID, APIKey, APISecret, gpt_url):
        self.APPID = APPID
        self.APIKey = APIKey
        self.APISecret = APISecret
        self.host = urlparse(gpt_url).netloc
        self.path = urlparse(gpt_url).path
        self.gpt_url = gpt_url

    # 生成url
    def create_url(self):
        # 生成RFC1123格式的时间戳
        now = datetime.now()
        date = format_date_time(mktime(now.timetuple()))

        # 拼接字符串
        signature_origin = "host: " + self.host + "\n"
        signature_origin += "date: " + date + "\n"
        signature_origin += "GET " + self.path + " HTTP/1.1"

        # 进行hmac-sha256进行加密
        signature_sha = hmac.new(self.APISecret.encode('utf-8'), signature_origin.encode('utf-8'),
                                 digestmod=hashlib.sha256).digest()

        signature_sha_base64 = base64.b64encode(signature_sha).decode(encoding='utf-8')

        authorization_origin = f'api_key="{self.APIKey}", algorithm="hmac-sha256", headers="host date request-line", signature="{signature_sha_base64}"'

        authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode(encoding='utf-8')

        # 将请求的鉴权参数组合为字典
        v = {
            "authorization": authorization,
            "date": date,
            "host": self.host
        }
        # 拼接鉴权参数，生成url
        url = self.gpt_url + '?' + urlencode(v)
        # 此处打印出建立连接时候的url,参考本demo的时候可取消上方打印的注释，比对相同参数时生成的url与自己代码生成的url是否一致
        return url


# 收到websocket错误的处理
def on_error(ws, error):
    print("### error:", error)


# 收到websocket关闭的处理
def on_close(ws,close_status_code, close_msg):
    print("### closed ###")


# 收到websocket连接建立的处理
def on_open(ws):
    thread.start_new_thread(run, (ws,))


def run(ws, *args):
    data = json.dumps(gen_params(appid=ws.appid, query=ws.query, domain=ws.domain))
    ws.send(data)


# 收到websocket消息的处理
def on_message(ws, message):
    # print(message)
    data = json.loads(message)
    code = data['header']['code']
    if code != 0:
        print(f'请求错误: {code}, {data}')
        ws.close()
    else:
        choices = data["payload"]["choices"]
        status = choices["status"]
        content = choices["text"][0]["content"]
        print(content,end='')
        if status == 2:
            print("#### 关闭会话")
            ws.close()


def gen_params(appid, query, domain):
    """
    通过appid和用户的提问来生成请参数
    """

    data = {
        "header": {
            "app_id": appid,
            "uid": "1234",           
            # "patch_id": []    #接入微调模型，对应服务发布后的resourceid          
        },
        "parameter": {
            "chat": {
                "domain": domain,
                "temperature": 0.5,
                "max_tokens": 4096,
                "auditing": "default",
            }
        },
        "payload": {
            "message": {
                "text": query
            }
        }
    }
    return data

def main(appid, api_secret, api_key, Spark_url, domain, query):
    wsParam = Ws_Param(appid, api_key, api_secret, Spark_url)
    websocket.enableTrace(False)
    wsUrl = wsParam.create_url()

    ws = websocket.WebSocketApp(wsUrl, on_message=on_message, on_error=on_error, on_close=on_close, on_open=on_open)
    ws.appid = appid
    ws.query = query
    ws.domain = domain
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})


text = []

# length = 0

def getText(role, content):
    jsoncon = {}

    history_put = """['工程','货物',]\n请从上面选项中选择一个属于下面文本的分类\n左侧边坡宣传标语
            ,结果只输出1,2 ,如果都不属于输出0
        """
    text.append({'role': 'user', 'content': history_put})
    text.append({'role': 'assistant', 'content': '0'})
    # # 设置对话背景或者模型角色
    # text.append({"role": "system", "content": "你现在扮演李白，你豪情万丈，狂放不羁；接下来请用李白的口吻和用户对话。"})
    jsoncon["role"] = role
    jsoncon["content"] = content
    text.append(jsoncon)
    return text

# 获取长度
def getlength(text):
    length = 0
    for content in text:
        temp = content["content"]
        leng = len(temp)
        length += leng
    return length

# 检测长度
def checklen(text):
    while getlength(text) > 8000:
        del text[0]
    return text

def detect_fake_news(query):
    #param query: 输入的新闻内容
    #return: 检测结果（是否为虚假新闻）

    # 构造虚假新闻检测的提示词
    prompt = f"""请判断以下新闻内容是否为虚假新闻，并给出判断理由：
新闻内容：{query}

请按照以下格式回答：
1. 判断结果：[是/否]
2. 判断理由：[理由]"""

    # 调用星火大模型进行检测
    result = main(
        appid="aa6753f8",
        api_secret="NjdkMjQwNmUxNmE0Nzg4N2I0YTAxMjVm",
        api_key="47bde95b69d50abf1a4d3411d72a2f74",
        Spark_url="wss://spark-api.xf-yun.com/v4.0/chat",
        domain="4.0Ultra",
        query=prompt
    )
    return result

def parse_detection_result(result):
    #param result: 星火大模型的返回结果
    #return: 解析后的结果（判断结果和理由）

    try:
        # 提取判断结果和理由
        lines = result.split("\n")
        judgment = lines[0].split("：")[1].strip()
        reason = lines[1].split("：")[1].strip()
        return judgment, reason
    except Exception as e:
        print("解析结果时出错：", e)
        return None, None

if __name__ == "__main__":
    text.clear()
    while 1:
        Input = input("\n" + "我：")
        query = checklen(getText("user",Input))
        answer = ""
        print("星火:",end="")
        main(
            appid="aa6753f8",
            api_secret="NjdkMjQwNmUxNmE0Nzg4N2I0YTAxMjVm",
            api_key="47bde95b69d50abf1a4d3411d72a2f74",
            #appid、api_secret、api_key三个服务认证信息请前往开放平台控制台查看（https://console.xfyun.cn/services/bm35）
            # Spark_url="wss://spark-api.xf-yun.com/v3.5/chat",      # Max环境的地址
            Spark_url = "wss://spark-api.xf-yun.com/v4.0/chat",  # 4.0Ultra环境的地址
            # Spark_url = "wss://spark-api.xf-yun.com/v3.1/chat"  # Pro环境的地址
            # Spark_url = "wss://spark-api.xf-yun.com/v1.1/chat"  # Lite环境的地址
            # domain="generalv3.5",     # Max版本
            domain = "4.0Ultra",     # 4.0Ultra 版本
            # domain = "generalv3"    # Pro版本
            # domain = "lite"      # Lite版本址
            query=query
        )

        #获得星火AI模型助手的回答
        getText("assistant",answer)


