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


class EmptyMobileConfirmation(Exception):
    pass
