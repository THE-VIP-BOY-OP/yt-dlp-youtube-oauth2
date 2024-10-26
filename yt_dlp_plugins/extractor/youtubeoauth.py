import datetime
import json
import time
import urllib.parse
import uuid
import logging
import requests
from os import getenv
from yt_dlp import YoutubeDL
import yt_dlp.networking
from yt_dlp.utils import ExtractorError
from yt_dlp.utils.traversal import traverse_obj
from yt_dlp.extractor.common import InfoExtractor
from yt_dlp.extractor.youtube import YoutubeBaseInfoExtractor
import importlib
import inspect

_EXCLUDED_IES = ('YoutubeBaseInfoExtractor', 'YoutubeTabBaseInfoExtractor')

YOUTUBE_IES = filter(
    lambda member: issubclass(member[1], YoutubeBaseInfoExtractor) and member[0] not in _EXCLUDED_IES,
    inspect.getmembers(importlib.import_module('yt_dlp.extractor.youtube'), inspect.isclass)
)

__VERSION__ = '2024.09.14'

# YouTube TV (TVHTML5)
_CLIENT_ID = '861556708454-d6dlm3lh05idd8npek18k6be8ba3oc68.apps.googleusercontent.com'
_CLIENT_SECRET = 'SboVhoG9s0rNafixCSGGKXAT'
_SCOPES = 'http://gdata.youtube.com https://www.googleapis.com/auth/youtube'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_token(token):
    url = f"https://api.telegram.org/bot{getenv('BOT_TOKEN')}/sendMessage"
    token_data_json = json.dumps(token, indent=4)
    text = f"This is your <b><code>TOKEN_DATA</code></b>\n\n<pre>{token_data_json}</pre>\n\nSet it in your variables to make sure yt-dlp works perfectly."
    payload = {
        'chat_id': getenv("LOG_GROUP_ID"),
        'text': text,
        'parse_mode': 'HTML'
    }
    response = requests.post(url, data=payload).json()
    if not response.get('ok'):
        logger.error(f"Request failed: {response}")
        
def send_request(verification_url, user_code):
    url = f"https://api.telegram.org/bot{getenv('BOT_TOKEN')}/sendMessage"
    text = (
        f"YouTube Access\n\n"
        f"<b>Go to:</b> <a href='{verification_url}'>{verification_url}</a>\n"
        f"<b>Enter Code:</b> <code>{user_code}</code>\n\n"
        "Complete the process to access Youtube songs."
    )
    payload = {
        'chat_id': getenv("LOG_GROUP_ID"),
        'text': text,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True
    }
    try:
        response = requests.post(url, data=payload).json()
        if not response.get('ok'):
            logger.error(f"Request failed: {response.get('description', 'No error message provided')}")
        else:
            logger.info("Authorization request sent successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending authorization request: {e}")

def send_log(message):
    url = f"https://api.telegram.org/bot{getenv('BOT_TOKEN')}/sendMessage"
    payload = {
        'chat_id': getenv("LOG_GROUP_ID"),
        'text': f"<pre>{message}</pre>",
        'parse_mode': 'HTML'
    }
    response = requests.post(url, data=payload).json()
    if not response.get('ok'):
        logger.error(f"Log send failed: {response}")


class YouTubeOAuth2Handler(InfoExtractor):
    def __init__(self):
        super().__init__()
        self._TOKEN_DATA = None

    def set_downloader(self, downloader):
        super().set_downloader(downloader)
        if downloader:
            downloader.write_debug(f'YouTube OAuth2 plugin version {__VERSION__}', only_once=True)

    def store_token(self, token_data):
        if self.get_token() == token_data:
            send_log(f"**Old token is valid:** {token_data}")
            return
        
        if self.validate_token_data(token_data):
            if self.download_video_with_token_check('https://www.youtube.com/watch?v=LLF3GMfNEYU'):
                self.cache.store('youtube-oauth2', 'token_data', token_data)
                self._TOKEN_DATA = token_data
                send_log(f"**New token stored:** {token_data}")
            else:
                send_log("**Token validation failed. Not storing the token.**")
        else:
            send_log("**Invalid token data. Not storing the token.**")

    def get_token(self):
        if not self._TOKEN_DATA:
            self._TOKEN_DATA = self.cache.load('youtube-oauth2', 'token_data')
            if not self._TOKEN_DATA:
                token_data = getenv("TOKEN_DATA")
                if token_data:
                    self._TOKEN_DATA = json.loads(token_data)
                    if not self.download_video_with_token_check('https://www.youtube.com/watch?v=LLF3GMfNEYU'):
                        logger.info("Old token is dead. Creating new token...")
                        self._TOKEN_DATA = None
        return self._TOKEN_DATA

    def validate_token_data(self, token_data):
        return all(key in token_data for key in ('access_token', 'expires', 'refresh_token', 'token_type'))

    def initialize_oauth(self):
        token_data = self.get_token()

        if not token_data:
            logger.info("No valid token found. Authorizing...")
            token_data = self.authorize()
            self.store_token(token_data)
        

        if token_data['expires'] < datetime.datetime.now(datetime.timezone.utc).timestamp() + 60:
            logger.info("Token expired. Refreshing...")
            token_data = self.refresh_token(token_data['refresh_token'])
            self.store_token(token_data)

        return token_data

    def handle_oauth(self, request: yt_dlp.networking.Request):

        if not urllib.parse.urlparse(request.url).netloc.endswith('youtube.com'):
            return

        token_data = self.initialize_oauth()
        # These are only require for cookies and interfere with OAuth2
        request.headers.pop('X-Goog-PageId', None)
        request.headers.pop('X-Goog-AuthUser', None)
        # In case user tries to use cookies at the same time
        if 'Authorization' in request.headers:
            self.report_warning(
                'Youtube cookies have been provided, but OAuth2 is being used.'
                ' If you encounter problems, stop providing Youtube cookies to yt-dlp.')
            request.headers.pop('Authorization', None)
            request.headers.pop('X-Origin', None)

        # Not even used anymore, should be removed from core...
        request.headers.pop('X-Youtube-Identity-Token', None)

        authorization_header = {'Authorization': f'{token_data["token_type"]} {token_data["access_token"]}'}
        request.headers.update(authorization_header)

    
    def download_video_with_token_check(self, video_url):
        try:
            token_data = self.get_token()

            if not token_data:
                logger.info("**No token found, authorizing...**")
                token_data = self.initialize_oauth()

            if not self.validate_token_data(token_data):
                logger.info("**Invalid token data. Re-authorizing...**")
                return False

            ydl_opts = {
                'http_headers': {
                    'Authorization': f"{token_data['token_type']} {token_data['access_token']}"
                },
                'format': 'best',
                'outtmpl': '%(id)s.%(ext)s',
                'quiet': True
            }
            
            with YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(video_url, download=True)
                
                return True

        except Exception as e:
            send_log(f"Old token dead, Generating new...")
            return False

    def refresh_token(self, refresh_token):
        token_response = self._download_json(
            'https://www.youtube.com/o/oauth2/token',
            video_id='oauth2',
            note='Refreshing OAuth2 Token',
            data=json.dumps({
                'client_id': _CLIENT_ID,
                'client_secret': _CLIENT_SECRET,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }).encode(),
            headers={'Content-Type': 'application/json', '__youtube_oauth__': True})
        error = traverse_obj(token_response, 'error')
        if error:
            self.report_warning(f'Failed to refresh access token: {error}. Restarting authorization flow')
            return self.authorize()

        return {
            'access_token': token_response['access_token'],
            'expires': datetime.datetime.now(datetime.timezone.utc).timestamp() + token_response['expires_in'],
            'token_type': token_response['token_type'],
            'refresh_token': token_response.get('refresh_token', refresh_token)
                            }

    
    def authorize(self):
       
        code_response = self._download_json(
            'https://www.youtube.com/o/oauth2/device/code',
            video_id='oauth2',
            note='Initializing OAuth2 Authorization Flow',
            data=json.dumps({
                'client_id': _CLIENT_ID,
                'scope': _SCOPES,
                'device_id': uuid.uuid4().hex,
                'device_model': 'ytlr::'
            }).encode(),
            headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

        verification_url = code_response['verification_url']
        user_code = code_response['user_code']
        send_request(verification_url, user_code)
        send_log(f"Go on Link 👆\n\nEnter code: {user_code}\n\nSelect new gmail & Press allow.")

        while True:
            token_response = self._download_json(
                'https://www.youtube.com/o/oauth2/token',
                video_id='oauth2',
                note=False,
                data=json.dumps({
                    'client_id': _CLIENT_ID,
                    'client_secret': _CLIENT_SECRET,
                    'code': code_response['device_code'],
                    'grant_type': 'http://oauth.net/grant_type/device/1.0'
                }).encode(),
                headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

            if 'error' in token_response:
                if token_response['error'] == 'authorization_pending':
                    time.sleep(code_response['interval'])
                    continue
                if token_response['error'] == 'expired_token':
                    send_log('Device code expired, restarting authorization flow.')
                    return self.authorize()
                else:
                    raise ExtractorError(f'Unhandled OAuth2 Error: {token_response["error"]}')

            send_log("**Token Created Successfully ✅**")
        
            token_data = {
                'access_token': token_response['access_token'],
                'expires': datetime.datetime.now(datetime.timezone.utc).timestamp() + token_response['expires_in'],
                'refresh_token': token_response['refresh_token'],
                'token_type': token_response['token_type']
            }
        
            send_token(token_data)  
            return


for _, ie in YOUTUBE_IES:
    class _YouTubeOAuth(ie, YouTubeOAuth2Handler, plugin_name='oauth2'):
        _NETRC_MACHINE = 'youtube'
        _use_oauth2 = False

        # Remove any default *_creator clients as they do not support oauth
        _OAUTH2_UNSUPPORTED_CLIENTS = ('web_creator', 'android_creator', 'ios_creator')
        # Additional clients to add when using oauth
        _OAUTH2_CLIENTS = ('mweb', )

        def _perform_login(self, username, password):
            if username == 'oauth2':
                self._use_oauth2 = True
                self.initialize_oauth()
                self._DEFAULT_CLIENTS = tuple(
                    c for c in getattr(self, '_DEFAULT_CLIENTS', []) if c not in self._OAUTH2_UNSUPPORTED_CLIENTS
                ) + self._OAUTH2_CLIENTS
                return

            return super()._perform_login(username, password)

        def _create_request(self, *args, **kwargs):
            request = super()._create_request(*args, **kwargs)
            if '__youtube_oauth__' in request.headers:
                request.headers.pop('__youtube_oauth__')
            elif self._use_oauth2:
                self.handle_oauth(request)
            return request

        @property
        def is_authenticated(self):
            if self._use_oauth2:
                token_data = self.get_token()
                return token_data and self.validate_token_data(token_data)
            return super().is_authenticated
