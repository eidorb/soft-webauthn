"""SoftWebauthnDevice serialization tests, mostly adapted from test_class.py"""

import pytest

from soft_webauthn import SoftWebauthnDevice

from .test_class import PKCCO, PKCRO, _device_assertions


def test_to_and_from_dict():
    """test to and from dict with create"""

    device = SoftWebauthnDevice()
    assert device.to_dict()

    device.create(PKCCO, 'https://example.org')

    serialized = device.to_dict()
    deserialized = SoftWebauthnDevice.from_dict(serialized)

    assert deserialized.private_key
    assert deserialized.rp_id == 'example.org'


def test_get_after_deserialize():
    """test get"""

    device = SoftWebauthnDevice()
    device.cred_init(PKCRO['publicKey']['rpId'], b'randomhandle')
    serialized = device.to_dict()
    deserialized = SoftWebauthnDevice.from_dict(serialized)

    _device_assertions(deserialized)
