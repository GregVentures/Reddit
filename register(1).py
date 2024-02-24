import uuid
from collections import namedtuple
import time
import hashlib
import hmac
from pprint import pprint
import colorama
import requests
import json
import faker
import random

def gen_username():
    fake  = faker.Faker()
    return fake.user_name()+str(random.randint(100,999))


# Constants
DEVICES = [
    ("samsung", "SM", "Galaxy"),
    ("LG", "LG", "Optimus"),
    ("HTC", "HTC", "One"),
    ("Motorola", "XT", "Droid"),
    ("Huawei", "HUAWEI", "Ascend"),
    ("ZTE", "ZTE", "Grand")
]
SIGNING_KEY = "8c7abaa5f905f70400c81bf3a1a101e75f7210104b1991f0cd5240aa80c4d99d" #Reddit's signing key
DEVELOPER_AD_ID= "8ef36104-bea8-411e-8759-5f5861a185ff" #Reddit's device advertiser ID

Device = namedtuple('Device', ['brand', 'code', 'name'])

class SessionTokenRefresher:
    """Helper class to handle session token epoch updates, for x-reddit-session and x-reddit-loid"""
    def __init__(self, token: str):
        # Split the token into its components
        parts = token.split('.')
        if len(parts) != 4:
            raise ValueError("Invalid token format")
        self.token_first_part = parts[0]
        self.token_second_part = parts[1]
        self.timestamp = int(parts[2])
        self.token_last_part = parts[3]

    def get_updated_token(self) -> str:
        """Update and return the token with the current timestamp"""
        current_timestamp = int(time.time() * 1000)  # Convert to millisecondsz`1
        updated_token = f"{self.token_first_part}.{self.token_second_part}.{current_timestamp}.{self.token_last_part}"
        return updated_token

class HmacSigner:
    def __init__(self, key=SIGNING_KEY):
        self.key = key

    def _hmac_sign(self, message: str) -> str:
        """Helper function to sign a message using HMAC."""
        return hmac.new(self.key.encode(), message.encode(), hashlib.sha256).hexdigest()

    def sign_body(self, epoch: int, body: str) -> str:
        formatted_body = f"Epoch:{epoch}|Body:{body}"
        return self._hmac_sign(formatted_body)

    def sign_result(self, epoch: int, user_agent: str, client_vendor_id: str) -> str:
        formatted_body = f"Epoch:{epoch}|User-Agent:{user_agent}|Client-Vendor-ID:{client_vendor_id}"
        return self._hmac_sign(formatted_body)

class RedditWrapper:
    def __init__(self):
        self.base_url = 'https://accounts.reddit.com'
        self.device = self._get_random_device()
        self.user_agent = f'Reddit/Version 2023.36.0/Build 1168982/Android 12'
        self.device_id = str(uuid.uuid4())
        self.headers = {
            'User-Agent': self.user_agent,
            'X-Reddit-Compression': '1',
            'X-Reddit-Qos': 'down-rate-mbps=3.200',
            'X-Reddit-Media-Codecs': 'available-codecs=video/avc, video/x-vnd.on2.vp9',
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Client-Vendor-Id': self.device_id
        }
        self.signer = HmacSigner()
        self.reddit_loid = None

    def _get_random_device(self):
        brand, code, name = random.choice(DEVICES)
        return Device(brand, code, name)

    def get_access_token(self):
        url = f'{self.base_url}/api/access_token'
        headers = self.headers.copy()
        headers['Authorization'] = 'Basic b2hYcG9xclpZdWIxa2c6'
        headers['X-Reddit-Retry'] = 'attempt=0, max=3, algo=full-jitter'
        body = {"scopes": ["*", "email", "pii"]}
        body_str = json.dumps(body)
        epoch = int(time.time())
        headers['X-Hmac-Signed-Body'] = self.signer.sign_body(epoch, body_str)
        headers['X-Hmac-Signed-Result'] = self.signer.sign_result(epoch, self.user_agent, self.device_id)
        response = requests.post(url, headers=headers, data=body_str)
        self.reddit_loid = response.headers.get('X-Reddit-Loid')
        return response.json()

    def register_user(self, username, password, email, newsletter_subscribe):
        if not self.reddit_loid:
            raise ValueError("X-Reddit-Loid is not set. Call get_access_token first.")
        url = f'{self.base_url}/api/register'
        headers = self.headers.copy()
        token_refresher = SessionTokenRefresher(self.reddit_loid)
        headers['X-Reddit-Loid'] = token_refresher.get_updated_token()
        body = {
            "username": username,
            "password": password,
            "email": email,
            "newsletter_subscribe": newsletter_subscribe
        }
        body_str = json.dumps(body)
        epoch = int(time.time())
        body_signature = self.signer.sign_body(epoch, body_str)
        result_signature = self.signer.sign_result(epoch, self.user_agent, self.device_id)
        headers['X-Hmac-Signed-Body'] = f"1:android:2:{epoch}:{body_signature}"
        headers['X-Hmac-Signed-Result'] = f"1:android:2:{epoch}:{result_signature}"
        response = requests.post(url, headers=headers, data=body_str)
        return response.json()


def my_ip():
    return requests.get('https://api.ipify.org').text

while True:
    user = gen_username()
    print(f"making user {user}")
    reddit = RedditWrapper()
    access_token_response = reddit.get_access_token()
    #pprint(access_token_response)

    register_user_response = reddit.register_user(user, 'Very_Secure_Password_999', f'{user}@vjuum.com', 'false')

    if register_user_response['success']:
        print(f"success! {user}")
        with open("users.txt", "a") as f:
            f.writelines(f"{user}\n")
    else:
        colorama.init()
        print(f"failed! {user}, reason: {register_user_response['error']['reason']}, details: {register_user_response['error']['explanation']}")

    time.sleep(5)
