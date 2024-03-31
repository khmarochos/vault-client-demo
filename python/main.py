import os
import time

import flask
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class Key:

    def generate(self, size: int = 2048) -> rsa.RSAPrivateKey:
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

    def __init__(self, directory: str, key: rsa.RSAPrivateKey, size: int = 2048, save: bool = False):
        self.private = key or self.generate(size)
        self.public = self.get_public()
        self.id = self.get_id()
        self.directory = directory
        self.file = f'{self.directory}/{self.id}.pem'
        if save:
            self.save()

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
        'keys_dir': {
            'command_line_parameter': '--keys-dir',
            'backing_environment_variable': 'KEYS_DIR',
            'description': 'Directory of public keys',
            'type': str,
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


if __name__ == '__main__':

    configuration = get_configuration()

    garbage_collection(configuration['keys_dir'])

    key = Key(configuration['keys_dir'], None, save=True)

    flask_app = flask.Flask(__name__)
    flask_app.run(
        debug=False,
        host='0.0.0.0',
        port=8080
    )
