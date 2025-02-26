from requests_oauthlib import OAuth2Session
from django.conf import settings

def get_oauth_session(state=None):
    """Initialize OAuth2Session with correct scopes including follows.write"""
    return OAuth2Session(
        client_id=settings.TWITTER_CLIENT_ID,
        redirect_uri=settings.TWITTER_REDIRECT_URI,
        scope=[
            "tweet.read",
            "tweet.write",
            "users.read",
            "like.write",
            "follows.write",
            "offline.access"
        ],
        state=state,
    )
