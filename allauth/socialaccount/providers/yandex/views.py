import requests

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import YandexProvider


class YandexOAuth2Adapter(OAuth2Adapter):
    provider_id = YandexProvider.id
    access_token_url = 'https://oauth.yandex.ru/token'
    authorize_url = 'https://oauth.yandex.ru/authorize'
    profile_url = 'https://login.yandex.ru/info'

    def complete_login(self, request, app, token, **kwargs):
        resp = requests.get(self.profile_url,
                            params={'oauth_token': token.token,
                                    'format': 'json'})
        resp.raise_for_status()
        extra_data = resp.json()
        login = self.get_provider() \
            .sociallogin_from_response(request,
                                       extra_data)
        return login


oauth2_login = OAuth2LoginView.adapter_view(YandexOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(YandexOAuth2Adapter)
