import base64
import time
import requests
from steampy import guard
import rsa
from steampy.models import SteamUrl
from steampy.exceptions import InvalidCredentials, CaptchaRequired, RuCaptchaError
from python_rucaptcha import ImageCaptcha


class LoginExecutor:

    def __init__(self, username: str, password: str, shared_secret: str, session: requests.Session, rucaptcha_key: str) -> None:
        self.username = username
        self.password = password
        self.one_time_code = ''
        self.shared_secret = shared_secret
        self.session = session
        self.rucaptcha_key = rucaptcha_key

    def login(self) -> requests.Session:
        try:
            login_response = self._send_login_request()
            self._check_for_captcha(login_response)
        except CaptchaRequired as e:
            image_link = 'https://store.steampowered.com/login/rendercaptcha/?gid={}'.format(e.captcha_gid)
            user_answer = ImageCaptcha.ImageCaptcha(rucaptcha_key=self.rucaptcha_key).captcha_handler(
                captcha_link=image_link
            )

            if user_answer['error']:
                raise RuCaptchaError(user_answer['error'])

            login_response = self._send_login_request({
                'captcha_text': user_answer['captchaSolve'],
                'captchagid': e.captcha_gid
            })

        self._check_for_captcha(login_response)

        login_response = self._enter_steam_guard_if_necessary(login_response)
        self._assert_valid_credentials(login_response)
        self._perform_redirects(login_response.json())
        self.set_sessionid_cookies()
        return self.session

    def _send_login_request(self, post_data=None):
        rsa_params = self._fetch_rsa_params()
        encrypted_password = self._encrypt_password(rsa_params)
        rsa_timestamp = rsa_params['rsa_timestamp']
        request_data = self._prepare_login_request_data(encrypted_password, rsa_timestamp)
        if post_data is not None:
            request_data.update(post_data)
        return self.session.post(SteamUrl.STORE_URL + '/login/dologin', data=request_data)

    def set_sessionid_cookies(self):
        sessionid = self.session.cookies.get_dict()['sessionid']
        community_domain = SteamUrl.COMMUNITY_URL[8:]
        store_domain = SteamUrl.STORE_URL[8:]
        community_cookie = self._create_session_id_cookie(sessionid, community_domain)
        store_cookie = self._create_session_id_cookie(sessionid, store_domain)
        self.session.cookies.set(**community_cookie)
        self.session.cookies.set(**store_cookie)

    @staticmethod
    def _create_session_id_cookie(sessionid: str, domain: str) -> dict:
        return {"name": "sessionid",
                "value": sessionid,
                "domain": domain}

    def _fetch_rsa_params(self, current_number_of_repetitions: int = 0) -> dict:
        maximal_number_of_repetitions = 5
        key_response = self.session.post(SteamUrl.STORE_URL + '/login/getrsakey/',
                                         data={'username': self.username}).json()
        try:
            rsa_mod = int(key_response['publickey_mod'], 16)
            rsa_exp = int(key_response['publickey_exp'], 16)
            rsa_timestamp = key_response['timestamp']
            return {'rsa_key': rsa.PublicKey(rsa_mod, rsa_exp),
                    'rsa_timestamp': rsa_timestamp}
        except KeyError:
            if current_number_of_repetitions < maximal_number_of_repetitions:
                return self._fetch_rsa_params(current_number_of_repetitions + 1)
            else:
                raise ValueError('Could not obtain rsa-key')

    def _encrypt_password(self, rsa_params: dict) -> str:
        return base64.b64encode(rsa.encrypt(self.password.encode('utf-8'), rsa_params['rsa_key']))

    def _prepare_login_request_data(self, encrypted_password, rsa_timestamp, captcha_gid=None, captcha_text=None):
        return {
            'password': encrypted_password,
            'username': self.username,
            'twofactorcode': self.one_time_code,
            'emailauth': '',
            'loginfriendlyname': '',
            'captchagid': captcha_gid or '-1',
            'captcha_text': captcha_text,
            'emailsteamid': '',
            'rsatimestamp': rsa_timestamp,
            'remember_login': 'true',
            'donotcache': str(int(time.time() * 1000))
        }

    @staticmethod
    def _check_for_captcha(login_response: requests.Response) -> None:
        res = login_response.json()
        if res.get('captcha_needed', False):
            raise CaptchaRequired(res['captcha_gid'])

    def _enter_steam_guard_if_necessary(self, login_response: requests.Response) -> requests.Response:
        if login_response.json()['requires_twofactor']:
            self.one_time_code = guard.generate_one_time_code(self.shared_secret)
            return self._send_login_request()
        return login_response

    @staticmethod
    def _assert_valid_credentials(login_response: requests.Response) -> None:
        response = login_response.json()
        if not response['success']:
            raise InvalidCredentials(response['message'])

    def _perform_redirects(self, response_dict: dict) -> None:
        parameters = response_dict.get('transfer_parameters')
        if parameters is None:
            raise Exception('Cannot perform redirects after login, no parameters fetched')
        for url in response_dict['transfer_urls']:
            self.session.post(url, parameters)

    def _fetch_home_page(self, session: requests.Session) -> requests.Response:
        return session.post(SteamUrl.COMMUNITY_URL + '/my/home/')
