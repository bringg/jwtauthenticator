from setuptools import setup

setup(
    name='jupyterhub-jwkauthenticator',
    version='0.3.0',
    description='JSONWebToken Authenticator for JupyterHub',
    url='https://github.com/bringg/jwtauthenticator',
    author='mogthesprog',
    author_email='mevanj89@gmail.com',
    license='Apache 2.0',
    tests_require = [
    'unittest2',
    ],
    test_suite = 'unittest2.collector',
    packages=['jwkauthenticator'],
    entry_points={
        'jupyterhub.authenticators': [
            'jwkauth = jwkauthenticator:JSONWebTokenAuthenticator',
        ],
    },
    install_requires=[
        'jupyterhub',
        'python-jose',
        'pyjwt',
        'requests',
    ]
)
