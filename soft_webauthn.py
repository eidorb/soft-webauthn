"""
Module implementing software webauthn token for testing webauthn enabled
applications
"""

import json
import os
from base64 import urlsafe_b64encode
from struct import pack
from typing import Dict, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData, CredentialCreationOptions, CredentialRequestOptions


class SoftWebauthnDevice():
    """
    This simulates the Webauthn browser API with a authenticator device
    connected. It's primary use-case is testing, device can hold only
    one credential.
    """

    def __init__(self):
        self.credential_id = b''
        self.private_key = b''
        self.aaguid = b'\x00'*16
        self.rp_id = ''
        self.user_handle = b''
        self.sign_count = 0

    def cred_init(self, rp_id, user_handle):
        """initialize credential for rp_id under user_handle"""

        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.rp_id = rp_id
        self.user_handle = user_handle

    def cred_as_attested(self):
        """return current credential as AttestedCredentialData"""

        return AttestedCredentialData.create(
            self.aaguid,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()))

    def create(self, options: Union[CredentialCreationOptions, Dict], origin: str):
        """create credential and return PublicKeyCredential object aka attestation"""

        if {'alg': -7, 'type': 'public-key'} not in options['publicKey']['pubKeyCredParams']:
            raise ValueError('Requested pubKeyCredParams does not contain supported type')

        if ('attestation' in options['publicKey']) and (options['publicKey']['attestation'] not in [None, 'none']):
            raise ValueError('Only none attestation supported')

        # prepare new key
        self.cred_init(options['publicKey']['rp']['id'], options['publicKey']['user']['id'])

        # generate credential response
        client_data = {
            'type': 'webauthn.create',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x41'  # attested_data + user_present
        sign_count = pack('>I', self.sign_count)
        credential_id_length = pack('>H', len(self.credential_id))
        cose_key = cbor.encode(ES256.from_cryptography_key(self.private_key.public_key()))
        attestation_object = {
            'authData':
                rp_id_hash + flags + sign_count
                + self.aaguid + credential_id_length + self.credential_id + cose_key,
            'fmt': 'none',
            'attStmt': {}
        }

        return {
            'id': urlsafe_b64encode(self.credential_id),
            'rawId': self.credential_id,
            'response': {
                'clientDataJSON': json.dumps(client_data).encode('utf-8'),
                'attestationObject': cbor.encode(attestation_object)
            },
            'type': 'public-key'
        }

    def get(self, options: Union[CredentialRequestOptions, Dict], origin: str):
        """get authentication credential aka assertion"""

        if self.rp_id != options['publicKey']['rpId']:
            raise ValueError('Requested rpID does not match current credential')

        self.sign_count += 1

        # prepare signature
        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }).encode('utf-8')
        client_data_hash = sha256(client_data)

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x01'
        sign_count = pack('>I', self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        signature = self.private_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

        # generate assertion
        return {
            'id': urlsafe_b64encode(self.credential_id),
            'rawId': self.credential_id,
            'response': {
                'authenticatorData': authenticator_data,
                'clientDataJSON': client_data,
                'signature': signature,
                'userHandle': self.user_handle
            },
            'type': 'public-key'
        }

    def to_dict(self) -> dict:
        """Convert the SoftWebauthnDevice object to a dictionary."""

        serialized_private_key = (
            b'' if self.private_key == b''
            else self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        return {
            'credential_id': self.credential_id,
            'serialized_private_key': serialized_private_key,
            'aaguid': self.aaguid,
            'rp_id': self.rp_id,
            'user_handle': self.user_handle,
            'sign_count': self.sign_count
        }

    @classmethod
    def from_dict(cls, data):
        """Create a SoftWebauthnDevice object from a dictionary."""

        device = cls()
        device.credential_id = data['credential_id']
        device.private_key = (
            b'' if data['serialized_private_key'] == b''
            else serialization.load_pem_private_key(
                data['serialized_private_key'],
                password=None,
                backend=default_backend()
            )
        )
        device.aaguid = data['aaguid']
        device.rp_id = data['rp_id']
        device.user_handle = data['user_handle']
        device.sign_count = data['sign_count']
        return device
