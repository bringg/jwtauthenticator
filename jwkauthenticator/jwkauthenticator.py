from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Bool
import jwt
import requests
import json


class JSONWebTokenLoginHandler(BaseHandler):
    def get(self):
        header_name = self.authenticator.header_name
        param_name = self.authenticator.param_name
        header_is_authorization = self.authenticator.header_is_authorization

        auth_header_content = self.request.headers.get(header_name, "")
        auth_cookie_content = self.get_cookie("XSRF-TOKEN", "")
        pkc_jwkset_path = self.authenticator.pkc_jwkset_path
        secret = self.authenticator.secret
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience
        tokenParam = self.get_argument(param_name, default=False)

        if auth_header_content and tokenParam:
            raise web.HTTPError(400)
        elif auth_header_content:
            if header_is_authorization:
                # we should not see "token" as first word in the AUTHORIZATION header, if we do it could mean someone coming in with a stale API token
                if auth_header_content.split()[0] != "bearer":
                    raise web.HTTPError(403)
                token = auth_header_content.split()[1]
            else:
                token = auth_header_content
        elif auth_cookie_content:
            token = auth_cookie_content
        elif tokenParam:
            token = tokenParam
        else:
            raise web.HTTPError(401)

        self.log.debug("Received token {token}".format(token=token))

        claims = ""
        if secret:
            claims = self.verify_jwt_using_secret(token, secret, audience)
        elif pkc_jwkset_path:
            claims = self.verify_jwt_with_claims(token, pkc_jwkset_path, audience)
        else:
            raise web.HTTPError(401)

        username = self.retrieve_username(claims, username_claim_field)
        username = self.authenticator.normalize_username(username)

        self.log.debug("Attempting to bind {username}".format(username=username))

        user = self.user_from_username(username)
        self.set_login_cookie(user)

        _url = url_path_join(self.hub.server.base_url, "home")
        next_url = self.get_argument("next", default=False)
        if next_url:
            _url = next_url

        self.redirect(_url)

    def verify_jwt_with_claims(self, token, pkc_jwkset_path, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            opts = {"verify_aud": False}
        else:
            opts = {}

        try:
            response = requests.get(pkc_jwkset_path)
            jwks = response.json()

            if "keys" not in jwks or len(jwks["keys"]) == 0:
                self.log.warn("Attempting to get jwks keys field, no keys found")
                raise Exception("no keys found")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwks["keys"][0])
            )

            self.log.debug("public key ready")

            return jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=audience,
                options=opts,
            )
        except:
            raise web.HTTPError(401)

    def verify_jwt_using_secret(self, json_web_token, secret, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            opts = {"verify_aud": False}
        else:
            opts = {}

        return jwt.decode(
            json_web_token,
            secret,
            algorithms=list(jwt.ALGORITHMS.SUPPORTED),
            audience=audience,
            options=opts,
        )

    def retrieve_username(self, claims, username_claim_field):
        # retrieve the username from the claims
        username = claims[username_claim_field]
        if "@" in username:
            # process username as if email, pull out string before '@' symbol
            return username.split("@")[0]

        else:
            # assume not username and return the user
            return username


class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header.
    """

    pkc_jwkset_path = Unicode(
        config=True,
        help="""
        A JSON Web Key (JWK) is a JSON object representing a public key.

        You can use one to verify a JWT issued by an OIDC provider signing its tokens with RS256. A JWK Set (JWKS) is a JSON object containing an array of public keys in use by an OIDC provider. See the JWK spec, RFC 7517, for official definitions.
        """,
    )

    username_claim_field = Unicode(
        default_value="upn",
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """,
    )

    expected_audience = Unicode(
        default_value="",
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""",
    )

    header_name = Unicode(
        default_value="Authorization",
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""",
    )

    header_is_authorization = Bool(
        default_value=True,
        config=True,
        help="""Treat the inspected header as an Authorization header.""",
    )

    param_name = Unicode(
        config=True,
        default_value="access_token",
        help="""The name of the query parameter used to specify the JWT token""",
    )

    secret = Unicode(
        config=True,
        help="""Shared secret key for siging JWT token.  If defined, it overrides any setting for signing_certificate""",
    )

    def get_handlers(self, app):
        return [
            (r"/login", JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """

    pass
