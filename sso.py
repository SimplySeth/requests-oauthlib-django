import os
import random
import string

from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.http import (
    HttpResponse,
    HttpResponseRedirect,
    HttpResponseServerError,
    JsonResponse,
)
from django.shortcuts import redirect, render, reverse
from django.urls import resolve, reverse

from requests_oauthlib import OAuth2Session

from .utils.logging import get_default_logger
log = get_default_logger(module="core.sso")

User = get_user_model()


"""
DEV ONLY !!!

This and using an http (as opposed to https) redirect_uri
"""
if settings.ENV == 'dev':
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

"""
END
"""
class Params:
    """
    A class for conveniently storing and building the necessary variables for
    SSO login.
    """

    def __init__(self,request,redirect_path='/ssoauth'):
        self.auth_url = settings.SSO_URL + "/as/authorization.oauth2"
        self.client_id = settings.SSO_CLIENT_ID
        self.client_secret = settings.SSO_API_KEY
        self.redirect_path = redirect_path
        self.request = request
        self.scope = "email groups openid profile"
        self.token_url = settings.SSO_URL + "/as/token.oauth2"
        self.userinfo_url = settings.SSO_URL + "/idp/userinfo.openid"

    def redirect_uri(self):
       """
       This function will ensure that:
       1> We have a full URL to the callback
       2> That dev gets an HTTP (as opposed to HTTPS) callback URL
       """
       request = self.request
       if settings.ENV == 'dev':
        uri = request.build_absolute_uri(self.redirect_path)
        redirect_uri = uri.replace('https','http')
       else:
        redirect_uri = request.build_absolute_uri(self.redirect_path)

       log.info("RedirectURI: {}".format(redirect_uri))
       return redirect_uri
      

def user_exists(email):
    """
    Check if a user account exists with the given email.

    Params:
        :email - the Intuit email to search with
    """

    try:
        users = list(User.objects.filter(email__iexact=email))
        for u in users:
            if u.username != email:
                return u
    except Exception as e:
        log.error(str(e))
        return None

def local_account(userinfo):
    """
    For each remote SSO account, there must be a corresponding
    local account. This function checks for a corresponding
    local account or creates one if it doesn't exist.

    Params:
        :userinfo - user object
    """
    email = userinfo.get("email")
    username = userinfo.get("preferred_username")

    # check with intuit email
    user = user_exists(email)
    if not user:
       return None
    else:
        return user


def admin_user(username):
    """
    Ensure the people in the Admin group have the
    `is_staff` and `is_superuser` flags enabled

    Params:
        :username - username of the target account
    """
    try:
        user = User.objects.get(username__iexact=username)
        if not user.is_staff:
            user.is_staff = True
            user.save()
        if not user.is_superuser:
            user.is_superuser = True
            user.save()
    except Exception as e:
        log.error(str(e))
        return None


def ssologin(request):
    """
      If SSO variables are not set, we shouldn't be at this view
      Try to redirect to the login page and preserve the get params
    """
    if not settings.SSO_AVAILABLE:
        return redirect(
            settings.LOGIN_REDIRECT_URL + "?{}".format(request.GET.urlencode())
        )
    """
      If a user comes to /hosts/ and they are not authenticated
      the login_required decorator will redirect to settings.LOGIN_URL + ?next=/hosts/
      in which case we want to hang on to that value so after the SSO dance we
      can continue to send the user to the correct URI they wanted.
    """
    n = request.GET.get("next")
    if n is not None and request.session.get("sso_next") != n:
        request.session["sso_next"] = n
        request.session.save()

    """
    prepare the request to PingFederate, then
    1. save state
    2. redirect to corresponsing PingFederate endpoint
    """
    params = Params(request=request)
    redirect_uri = params.redirect_uri()
    oauth = OAuth2Session(client_id=params.client_id, redirect_uri=redirect_uri, scope=params.scope)
    authorization_url, state = oauth.authorization_url(params.auth_url)
    request.session["oauth_state"] = state
    request.session.modified = True
    request.session.save()
    return HttpResponseRedirect(authorization_url)


def ssoauth(request):
    """
    Callback function in response to the redirect from the PingFederate endpoint.
    """
    params = Params(request=request)
    redirect_uri = params.redirect_uri()
    oauth = OAuth2Session(
        client_id=params.client_id,
        redirect_uri=redirect_uri,
        scope=params.scope,
        state=request.GET.get("state"),
    )
    # Fetch the auth token ...
    token = oauth.fetch_token(
        token_url=params.token_url,
        client_secret=params.client_secret,
        code=request.GET.get("code"),
        include_client_id=True,
        method="POST")

    # save the token in the session
    request.session["oauth_token"] = token
    request.session.save()

    # attempt to retreive the user info ...
    try:
        u = oauth.get(params.userinfo_url)
    except Exception as e:
        log.error("Userinfo retrieval failed: {0}".format(str(e)))
        return HttpResponseServerError()

    # if user info retrieval successful ...
    if u.status_code == 200:
        # get the response as json
        data = u.json()
        # get the list of groups
        groups = data.get("groups")
        # check to make sure the user attempting to login is in the correct group
        if "Access" or "Admin" in groups:
            user = local_account(data)
            """
            if the user is in the `Admin` group,
            ensure that `is_staff` and `is_superuser` user permissions are set
            """
            if "Admin" in groups:
                admin_user(user.username)

            # log the user in using Django login, with the retrieved user object
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")

            # redirect to the path the user came in on
            return redirect(request.session.pop("sso_next", settings.LOGIN_REDIRECT_URL))
        else:
            return HttpResponse("Unauthorized", status=401)
    else:
        log.error(
            "{0} returned an error of {1}".format(settings.SSO_URL, u.status_code)
        )
        return HttpResponseServerError()
