"""Tests conversion of SoftWebauthnDevice to/from dict."""

from soft_webauthn import SoftWebauthnDevice, from_dict, to_dict

from .test_class import PKCCO


def test_to_dict():
    """Tests conversion to dict."""
    device = SoftWebauthnDevice()
    device_dict = to_dict(device)

    assert device_dict["credential_id"] is None
    assert device_dict["serialized_private_key"] is None
    assert device_dict["aaguid"] == b"\x00" * 16
    assert device_dict["rp_id"] is None
    assert device_dict["user_handle"] is None
    assert device_dict["sign_count"] == 0

    device.create(PKCCO, "https://example.org")
    device_dict = to_dict(device)

    assert device_dict["credential_id"]
    assert device_dict["serialized_private_key"]
    assert device_dict["aaguid"] == b"\x00" * 16
    assert device_dict["rp_id"] == "example.org"
    assert device_dict["user_handle"] == b"randomhandle"
    assert device_dict["sign_count"] == 0


def test_from_dict():
    """Tests conversion from dict."""
    # Uninitialised cred.
    device = from_dict(
        {
            "credential_id": None,
            "serialized_private_key": None,
            "aaguid": b"\x00" * 16,
            "rp_id": None,
            "user_handle": None,
            "sign_count": 0,
        }
    )
    assert device.credential_id is None
    assert device.private_key is None
    assert device.aaguid == b"\x00" * 16
    assert device.rp_id is None
    assert device.user_handle is None
    assert device.sign_count == 0

    device = from_dict(
        {
            "credential_id": b"randomcred",
            "serialized_private_key": (  # are the secrets police gonna get me?
                b"-----BEGIN PRIVATE KEY-----\n"
                b"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga5UHq+nz0X/clYan\n"
                b"rz1HVTozJo1idwj5ueZQpMYwNXOhRANCAARft/dYDRjHbv0qM5zgOnJ2rT08KN4X\n"
                b"sRFjyUxcWMT1ckMIvu7Gvr9JH1NyTQmVn7fbMLsaALB2TGmi9Mds+tM3\n"
                b"-----END PRIVATE KEY-----\n"
            ),
            "aaguid": b"\x00" * 16,
            "rp_id": "example.org",
            "user_handle": b"randomhandle",
            "sign_count": 0,
        }
    )
    assert device.credential_id == b"randomcred"
    assert device.private_key
    assert device.aaguid == b"\x00" * 16
    assert device.rp_id == "example.org"
    assert device.user_handle == b"randomhandle"
    assert device.sign_count == 0
