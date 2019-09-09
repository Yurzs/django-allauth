from allauth.account.models import EmailAddress
from allauth.socialaccount.app_settings import QUERY_EMAIL
from allauth.socialaccount.providers.base import AuthAction, ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider

class Scope(object):
    EMAIL = 'email'
    PROFILE = 'profile'


class YandexAccount(ProviderAccount):

    def get_profile_url(self):
        return self.account.extra_data.get('link', None)

    def get_avatar_url(self):
        return self.account.extra_data.get('default_avatar_id', None)

    def to_str(self):
        dflt = super(YandexAccount, self).to_str()
        return self.account.extra_data.get('display_name', dflt)


class YandexProvider(OAuth2Provider):
    id = 'yandex'
    name = 'Yandex'
    account_class = YandexAccount

    def get_default_scope(self):
        scope = [Scope.PROFILE]
        if QUERY_EMAIL:
            scope.append(Scope.EMAIL)
        return scope

    def get_auth_params(self, request, action):
        ret = super(YandexProvider, self).get_auth_params(request,
                                                          action)
        if action == AuthAction.REAUTHENTICATE:
            ret['prompt'] = 'select_account consent'
        return ret

    def extract_uid(self, data):
        return str(data['id'])

    def extract_common_fields(self, data):
        try:
            return dict(email=data.get('default_email'),
                        last_name=data.get('last_name'),
                        first_name=data.get('first_name'))
        except IndexError:
            return dict(email=data.get('default_email'))

    def extract_email_addresses(self, data):
        ret = []
        email = data.get('default_email')
        if email and data.get('verified_email'):
            ret.append(EmailAddress(email=email,
                       verified=True,
                       primary=True))
        return ret


provider_classes = [YandexProvider]
