import threading, os, ctypes, time, tls_client, json, sys, re
from base64 import b64encode, urlsafe_b64decode
from itertools import cycle
import requests, uuid
from colorama import Fore, init
from datetime import datetime

print("Loading config")

f = open("input/config.json", "r").read()
config = json.loads(f)
__useragent__ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
proxyless = config["proxyless"]
debug = config["debug"]
threads = config["threads"]
delay = config["delay"]
max_retries = config["max_retries"]
client_id = config["client_id"]
secret = config["client_secret"]
redirect = config["redirect_uri"]
proxyless = config["proxyless"]
include_tokens = config["include_tokens"]
out_file = config["output"]

tkW = open("output/tokens-worked.txt", "a")
print("Loading proxies")
time.sleep(1)
with open("input/proxies.txt", "r", encoding="utf-8") as f:
    proxies = cycle(f.read().splitlines())


def get_proxy():
    return next(proxies)


def get_build_number():
    try:
        site = requests.get("https://discord.com/login").text
        build_number_asset = (
            "https://discord.com/assets/"
            + re.compile(r"assets/+([a-z0-9]+)\.js").findall(site)[-2]
            + ".js"
        )
        asset_text = requests.get(build_number_asset).text
        build_number = asset_text.find("buildNumber") + 24
        return int(asset_text[build_number : build_number + 6])
    except Exception:
        return 236850


build_number = get_build_number()
cv = "108.0.5359.215"
__properties__ = b64encode(
    json.dumps(
        {
            "os": "Windows",
            "browser": "Discord Client",
            "release_channel": "stable",
            "client_version": "1.0.9013",
            "os_version": "10.0.19045",
            "os_arch": "x64",
            "system_locale": "en-US",
            "client_build_number": build_number,
            "native_build_number": 32266,
            "client_version_string": "1.0.9013",
        },
        separators=(",", ":"),
    ).encode()
).decode()
authed_ = []


def get_headers(token):
    headers = {
        "Authorization": token,
        "Accept-Encoding": "deflate",
        "Origin": "https://discord.com",
        "Accept": "*/*",
        "DNT": "1",
        "X-Discord-Locale": "en-US",
        "sec-ch-ua": '"Not?A_Brand";v="8", "Chromium";v="108"',
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-ch-ua-mobile": "?0",
        "X-Super-Properties": __properties__,
        "User-Agent": __useragent__,
        "Referer": "https://discord.com/channels/@me",
        "X-Debug-Options": "bugReporterEnabled",
        "Content-Type": "application/json",
        "X-Discord-Timezone": "Asia/Calcutta",
        "cookie": "__dcfduid=23a63d20476c11ec9811c1e6024b99d9; __sdcfduid=23a63d21476c11ec9811c1e6024b99d9e7175a1ac31a8c5e4152455c5056eff033528243e185c5a85202515edb6d57b0; locale=en-GB",
        "te": "trailers",
    }
    return headers


os.system("cls")
authorized = 0
failed = 0
total = 0
saver_total = 0
now = datetime.now()
formatted_time = now.strftime("[%H:%M:%S]")
tkns_loaded = len(open("input/tokens.txt").readlines())

init(convert=True, strip=False)
green = Fore.CYAN
reset = Fore.RESET
screen = f"""

{green}{formatted_time}{reset} Tokens: {tkns_loaded}
{green}{formatted_time}{reset} Proxyless: {proxyless}
{green}{formatted_time}{reset} Proxies: {len(open("input/proxies.txt").readlines())}
{green}{formatted_time}{reset} Fetching discord build number at discord.com
{green}{formatted_time}{reset} Successfully grabbed latest build number [{build_number}]
{green}{formatted_time}{reset} Discord API Version : v9

"""
print(screen)
time.sleep(5)
auth = f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect}&response_type=code&scope=identify%20guilds.join"


def title():
    ctypes.windll.kernel32.SetConsoleTitleW(
        "[Developer] Mascular1337 | Tokens: %s | Total Requests: %s | Authorized: %s | Failed: %s"
        % (tkns_loaded, total, authorized, failed)
    )


af = open("output/cache.txt", "a", encoding="utf-8")
authed_ = ""


def getCookies(proxy) -> list:
    for i in range(max_retries):
        try:
            headers = {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Referer": "https://discord.com/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Sec-GPC": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
                "X-Track": __properties__,
            }
            session = tls_client.Session(
                client_identifier="chrome117", random_tls_extension_order=True
            )
            resp = session.get(
                "https://discord.com/api/v9/experiments",
                headers=headers,
                proxy="http://" + proxy,
            )
            return resp.cookies, resp.json().get(
                "fingerprint"
            )
        except Exception as e:
            if debug:
                time_now = datetime.now()
                current_time = time_now.strftime("[%H:%M:%S]")
                print(f"{current_time} [DEBUG]: ", e)
            continue


def authorizer(token):
    headers = get_headers(token)
    headers[
        "X-Fingerprint"
    ] = "1162011318769950780.McNABsA9abn1vpFUVhqyog2kVm0"
    cookies = {
        "__dcfduid": "9fa07fd468fe11ee9eddaea6cf6ac781",
        "__sdcfduid": "9fa07fd468fe11ee9eddaea6cf6ac7815a10a14b2ee443499d7d53c8cb9e5c016086b1aca1e62c80d8d98463177d00b8",
        "__cfruid": "56f1219c13f0831ee60503ee02415333302f7bee-1697115330",
        "locale": "en-US",
    }
    global authorized, authed_, failed, total, saver_total
    if not proxyless:
        proxy = get_proxy()
        proxy_dict = "http://" + proxy
        try:
            cookies_res, x_fingerprint = getCookies(proxy)
            cookies = {
                "__dcfduid": cookies_res.get("__dcfduid"),
                "__sdcfduid": cookies_res.get("__sdcfduid"),
                "__cfruid": cookies_res.get("__cfruid"),
                "locale": "en-US",
            }
            headers.update(
                {
                    "Cookie": "; ".join(
                        [
                            f"{a}={b}"
                            for a, b in cookies.items()
                        ]
                    )
                }
            )
            headers["X-Fingerprint"] = x_fingerprint
        except Exception as e:
            pass
    for i in range(max_retries):
        total += 1
        try:
            session = tls_client.Session(
                client_identifier="chrome117", random_tls_extension_order=True
            )
            session.headers.update(headers)
            resp_json = {"authorize": "true", "permissions": "0"}
            resp = session.post(
                auth, json=resp_json, proxy=proxy_dict
            )
            if resp.status_code in (200, 201, 204):
                location = resp.json()["location"]
                code = location.replace(f"{redirect}?code=", "")
                resp_json = {
                    "client_id": client_id,
                    "client_secret": secret,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect,
                }
                resp = tls_client.Session(
                    client_identifier="chrome117", random_tls_extension_order=True
                ).post(
                    "https://discord.com/api/v9/oauth2/token",
                    data=resp_json,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept-Encoding": "deflate",
                    },
                    proxy=proxy_dict,
                )
                if not resp.status_code in (200, 201, 204):
                    continue
                resp_json = resp.json()
                access_token = resp_json["access_token"]
                refresh_token = resp_json["refresh_token"]
                token_split = urlsafe_b64decode(
                    token.split(".")[0] + "=="
                ).decode("utf-8")
                if include_tokens:
                    authed_token = f"{token_split}:{access_token}:{refresh_token}:{token}\n"
                else:
                    authed_token = (
                        f"{token_split}:{access_token}:{refresh_token}\n"
                    )
                authed_ += authed_token
                af.write(authed_token)
                tkW.write(token + "\n")
                authorized += 1
                title()
                time_now = datetime.now()
                current_time = time_now.strftime("[%H:%M:%S]")
                print(
                    f"{current_time} {authorized} {green}Authorized{reset}: ",
                    token[:50] + "****************************",
                )
                saver_total += 1
                break
            else:
                if debug:
                    print(
                        f"{current_time} [DEBUG]: Failed to Authorize: ",
                        token,
                        resp.text,
                    )
                saver_total += 1
                failed += 1
                title()
                break
        except Exception as e:
            if debug:
                time_now = datetime.now()
                current_time = time_now.strftime("[%H:%M:%S]")
                print(
                    f"{current_time} [DEBUG]: Failed to Authorize: ",
                    token,
                    e,
                )
            failed += 1
            saver_total += 1
            title()
            continue


f = open("input/tokens.txt", "r").read().splitlines()


def start():
    global delay
    for i in f:
        i = i.strip()
        try:
            splitted_thing = i.split(":")[2]
        except:
            splitted_thing = i
            
        if proxyless and delay < 0.11:
            delay = 0.1
        elif delay < 0.05:
            delay = 0.05
        time.sleep(delay)
        try:
            thread = threading.Thread(
                target=authorizer, args=(splitted_thing,)
            ).start()
        except:
            pass


start()


def save():
    time.sleep(2)
    while True:
        time.sleep(1)
        global saver_total
        if saver_total >= tkns_loaded:
            af.close()
            tkW.close()
            open(out_file, "a").close()
            file = open(out_file, "w")
            file.write(authed_)
            file.close()
            time_now = datetime.now()
            current_time = time_now.strftime("[%H:%M:%S]")
            print(
                "\n\n%s [INFO]: Total Requests: %s | Authorized: %s | Failed: %s"
                % (current_time, total, authorized, failed)
            )
            choice = input("Press Enter to exit > ")
            break
        else:
            continue


save()
