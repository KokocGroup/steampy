class SevenDaysHoldException(Exception):
    pass


class TooManyRequests(Exception):
    pass


class ApiException(Exception):
    pass


class LoginRequired(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class NullInventory(Exception):
    pass


class CaptchaRequired(Exception):
    def __init__(self, captcha_gid, *args, **kwargs):
        super(CaptchaRequired, self).__init__(*args, **kwargs)
        self.captcha_gid = captcha_gid


class ConfirmationExpected(Exception):
    pass


class RuCaptchaError(Exception):
    pass


class BannedError(Exception):
    pass


class BadResponse(Exception):

    def __init__(self, response):
        self.response = response
        super(BadResponse, self).__init__("Bad response: {}".format(response.status_code))


class EmptyMobileConfirmation(Exception):
    pass
