import os
import time

import flask
import requests
import argparse
import base64
import jwt
import hvac
import logging
from multiprocessing import Process
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class Key:

    def generate(self, size: int) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )

    def get_public(self) -> rsa.RSAPublicKey:
        return self.private.public_key()

    def get_id(self) -> str:
        der = self.public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
        fingerprint.update(der)
        return fingerprint.finalize().hex()

    def __str__(self) -> str:
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def save(self) -> str:
        if not os.path.exists(self.directory):
            raise FileNotFoundError(f"Directory {self.directory} does not exist")
        with open(self.file, 'w') as file:
            file.write(self.__str__())

    def __init__(
            self,
            key: rsa.RSAPrivateKey | rsa.RSAPublicKey | None,
            directory: str,
            size: int,
            save: bool = False,
    ):
        if key is rsa.RSAPrivateKey:
            self.private = key
            self.public = self.get_public()
        elif key is rsa.RSAPublicKey:
            self.private = None
            self.public = key
        else:
            self.private = self.generate(size)
            self.public = self.get_public()
        self.id = self.get_id()
        self.directory = directory
        self.file = f'{self.directory}/{self.id}.pem'
        if save:
            self.save()


class Vault:

    def __init__(self, url: str, ca_bundle: str = None):
        self.url = url
        self.ca_bundle = ca_bundle
        self.client = hvac.Client(url=self.url, verify=self.ca_bundle)

    def auth(self, jwt: str, role: str, path: str) -> str:
        response = self.client.auth.jwt.jwt_login(
            role=role,
            path=path,
            jwt=jwt,
        )
        return response['auth']['client_token']


def get_configuration() -> dict:

    configuration = {}

    configuration_mapping = {
        'vault_url': {
            'command_line_parameter': '--vault-url',
            'backing_environment_variable': 'VAULT_URL',
            'description': 'URL of Vault API',
            'type': str,
            'required_argument': False,
            'required': True
        },
        'vault_ca': {
            'command_line_parameter': '--vault-ca',
            'backing_environment_variable': 'VAULT_CA',
            'description': 'Path to CA certificate of Vault',
            'type': str,
            'required_argument': False,
            'required': False
        },
        'vault_role': {
            'command_line_parameter': '--vault-role',
            'backing_environment_variable': 'VAULT_ROLE',
            'description': 'Role to authenticate with',
            'type': str,
            'required_argument': False,
            'required': True
        },
        'vault_auth_path': {
            'command_line_parameter': '--vault-auth-path',
            'backing_environment_variable': 'VAULT_AUTH_PATH',
            'description': 'Path to authenticate with',
            'type': str,
            'required_argument': False,
            'required': True
        },
        'keys_dir': {
            'command_line_parameter': '--keys-dir',
            'backing_environment_variable': 'KEYS_DIR',
            'description': 'Directory of public keys',
            'type': str,
            'required_argument': False,
            'required': True
        },
        'keys_size': {
            'command_line_parameter': '--keys-size',
            'backing_environment_variable': 'KEYS_SIZE',
            'description': 'Size of RSA keys',
            'type': int,
            'required_argument': False,
            'required': True
        },
        'secret_path': {
            'command_line_parameter': '--secret-path',
            'backing_environment_variable': 'SECRET_PATH',
            'description': 'Secret to fetch from Vault',
            'type': str,
            'required_argument': False,
            'required': True
        },
        'jwks_port': {
            'command_line_parameter': '--jwks-port',
            'backing_environment_variable': 'JWKS_PORT',
            'description': 'Port to listen on for JWKS endpoint"',
            'type': int,
            'required_argument': False,
            'required': True
        }
    }

    argument_parser = argparse.ArgumentParser(description='Yet another demo-application interacting with Vault.')
    for parameter, settings in configuration_mapping.items():
        argument_parser.add_argument(
            settings["command_line_parameter"],
            required=settings['required_argument'],
            dest=parameter,
            type=settings['type'],
            help="{:s} (fallback variable is {:s})".format(
                settings['description'],
                settings['backing_environment_variable']
            ),
            metavar=f'<{parameter}>'
        )

    argument_parser_result = argument_parser.parse_args()

    for parameter, settings in configuration_mapping.items():
        if getattr(argument_parser_result, parameter, None) is None:
            configuration[parameter] = os.environ.get(settings['backing_environment_variable'])
        else:
            configuration[parameter] = getattr(argument_parser_result, parameter)
        if configuration[parameter] is None and settings['required']:
            raise ValueError("Missing configuration parameter: {:s}, go get some --help".format(parameter))

    return configuration


def garbage_collection(path: str):
    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        if os.path.isfile(file_path):
            if os.path.getmtime(file_path) < time.time() - 3 * 3600:
                os.remove(file_path)


def form_jwks(path: str):

    def int_to_base64url(value: int) -> str:
        return \
            base64.urlsafe_b64encode(
                value.to_bytes(
                    (value.bit_length() + 7) // 8,
                    byteorder='big'
                )
            ) \
                .decode('utf-8') \
                .rstrip('=')

    jwks = {
        "keys": []
    }
    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                key_loaded = file.read()
                key_imported = serialization.load_pem_public_key(key_loaded.encode('utf-8'), default_backend())
                key = Key(
                    key_imported,
                    path,
                    key_imported.key_size,
                    save=False
                )
                jwks['keys'].append({
                    "kty": "RSA",
                    "use": "sig",
                    "kid": key.get_id(),
                    "e": int_to_base64url(key_imported.public_numbers().e),
                    "n": int_to_base64url(key_imported.public_numbers().n),
                    "alg": "RS256"
                })
    return jwks


def form_jwt(private_key: rsa.RSAPrivateKey, audience: str) -> str:
    current_time = time.time()
    payload = {
        "iat": int(current_time),
        "exp": int(current_time) + (5 * 60),
        "sub": "vault-client-demo",
        "aud": audience,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG)

    configuration = get_configuration()

    garbage_collection(configuration['keys_dir'])

    flask_app = flask.Flask(__name__)

    @flask_app.route('/jwks')
    def flask_jwks():
        return form_jwks(configuration['keys_dir'])

    key = Key(None, configuration['keys_dir'], configuration['keys_size'], True)

    flask_process = Process(
        target=flask_app.run,
        kwargs={
            'host': '0.0.0.0',
            'port': configuration['jwks_port'],
            'debug': False
        }
    )
    flask_process.start()

    while True:
        try:
            response = requests.get(f"http://localhost:{ configuration['jwks_port'] }/jwks")
            if response.status_code == 200:
                logging.info("JWKS endpoint is ready")
                break
        except requests.ConnectionError:
            pass
        logging.warning("JWKS endpoint is not ready yet")
        time.sleep(1)

    # Create a JWS token here
    jwt = form_jwt(key.private, 'vault-client-demo')
    logging.debug(f"JWT token: { jwt }")

    vault = Vault(configuration['vault_url'], configuration['vault_ca'])
    vault_token = vault.auth(jwt, configuration['vault_role'], configuration['vault_auth_path'])
    logging.debug(f"Vault token: { vault_token }")

    secret_path_components = configuration['secret_path'].split('/')
    secret = vault.client.secrets.kv.v2.read_secret_version(
        mount_point=secret_path_components[0],
        path='/'.join(secret_path_components[1:]),
        raise_on_deleted_version=True,
    )

    logging.info(f"Wow, we've finally got something: { secret['data']['data'] }")

    time.sleep(86400)

    flask_process.terminate()
    flask_process.join()
    os.remove(key.file)

