# Web 流量分析平台

一个基于 Flask 的轻量级 Web 流量分析工具，支持 PCAP 文件上传、HTTP 流量解析、自定义规则处理以及强大的流量搜索功能。

## 🚀 功能特性

- **PCAP 后台解析**：支持上传 PCAP 文件，利用 `tshark` 在后台异步解析 HTTP 流量。
- **强大的搜索语法**：内置搜索编译器，支持按 Host、Method、URI、状态码、报文内容等进行组合查询。
- **动态规则引擎**：支持编写 Python 脚本实时处理流量（如：自动 AES 解密、XOR 解码、Base64 转换等），并提供试运行模拟功能。
- **交互式详情视图**：
    - 支持多种字符编码（UTF-8, GBK, HEX）。
    - 支持 URL 解码与 Header 隐藏。
    - 自动关联请求与响应帧。
- **规则管理**：支持规则的优先级排序、导出与导入（JSON 格式）。
- **现代化 UI**：基于 Bootstrap 5 与 Bootstrap Icons 构建。

## 🛠️ 环境要求

- **Python**: 3.12+
- **Wireshark/Tshark**: 系统必须安装 `tshark` 并在环境变量中可用（用于解析 PCAP）。
- **SQLite**: 默认使用 SQLite 存储（位于 `instance/` 目录）。

## 📦 安装与运行

1. **克隆项目**：
   
   /
   
2. **安装依赖**：
   
   /
   
3. **初始化与运行**：
   
   /
   
4. **访问地址**：
   打开浏览器访问 `http://127.0.0.1:5000`

## 📂 目录结构

- `/instance`: 存储上传的 PCAP 原文件及 SQLite 数据库。

## 📝 规则编写示例

在“规则管理”中，你可以编写如下 Python 代码来处理流量：

```python
# 示例：对包含特定特征的请求体进行 Base64 解码
import base64

def process(flow):
    if flow.request_body and b"data=" in flow.request_body:
        try:
            # 假设数据在 data= 之后
            parts = flow.request_body.split(b"data=")
            decoded = base64.b64decode(parts[1])
            flow.request_body = parts[0] + b"data=" + decoded
        except:
            pass
    return flow
```

补充示例

```
import binascii
from urllib.parse import parse_qs
RC4_SECRET = b'v1p3r_5tr1k3_k3y'
def rc4_crypt(data: bytes, key: bytes) -> bytes:
        S = list(range(256))
        j = 0
        for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
        i = j = 0
        res = bytearray()
        for char in data:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                res.append(char ^ S[(S[i] + S[j]) % 256])
        return bytes(res)
def process(flow):
    parse_qs_body = parse_qs(flow.request_body.decode())
    decrypt = b''
    for k, v in parse_qs_body.items():
        if isinstance(v, list) and len(v) == 1:
            v = v[0]
        enc_cmd = binascii.unhexlify(v)
        cmd = rc4_crypt(enc_cmd, RC4_SECRET)
        decrypt += k.encode() + b"=" + cmd
    flow.request_body = decrypt 
    enc_output = binascii.unhexlify(flow.response_body.decode())
    output_bytes = rc4_crypt(enc_output, RC4_SECRET)
    flow.response_body = output_bytes

```



## ⚠️ 注意事项

1. **Tshark 依赖**：如果无法解析 PCAP，请检查终端输入 `tshark -v` 是否有输出。
2. **性能建议**：对于超大型 PCAP（>500MB），解析可能需要较长时间，请在后台任务列表中查看进度。
3. **安全提示**：规则引擎支持执行 Python 代码，请仅导入受信任的规则集。
