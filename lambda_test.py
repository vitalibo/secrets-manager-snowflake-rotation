from unittest import mock

import pytest

lambda_module = __import__('lambda')


@pytest.mark.parametrize('rsa_public_key_fp, rsa_public_key_2_fp, expected', [
    ('null', 'null', 'RSA_PUBLIC_KEY'),
    ('SHA256:/CURRENT_RSA_PUBLIC_KEY_FP', 'null', 'RSA_PUBLIC_KEY_2'),
    ('null', 'SHA256:/CURRENT_RSA_PUBLIC_KEY_FP', 'RSA_PUBLIC_KEY'),
    ('SHA256:/CURRENT_RSA_PUBLIC_KEY_FP', 'SHA256:/PREVIOUS_RSA_PUBLIC_KEY_FP', 'RSA_PUBLIC_KEY_2'),
    ('SHA256:/PREVIOUS_RSA_PUBLIC_KEY_FP', 'SHA256:/CURRENT_RSA_PUBLIC_KEY_FP', 'RSA_PUBLIC_KEY'),
    ('SHA256:/UNKNOWN_RSA_PUBLIC_KEY_FP', 'SHA256:/PREVIOUS_RSA_PUBLIC_KEY_FP', 'RSA_PUBLIC_KEY'),
    ('SHA256:/PREVIOUS_RSA_PUBLIC_KEY_FP', 'SHA256:/UNKNOWN_RSA_PUBLIC_KEY_FP', 'RSA_PUBLIC_KEY'),
])
def test_get_public_key_property(rsa_public_key_fp, rsa_public_key_2_fp, expected):
    mock_conn = mock.Mock()
    mock_cursor = mock.MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.__iter__.return_value = iter([
        ('RSA_PUBLIC_KEY', 'MIIBIjANBgkqhk', 'null', 'RSA public key of the user'),
        ('RSA_PUBLIC_KEY_FP', rsa_public_key_fp, 'null', 'Fingerprint of the RSA public key'),
        ('RSA_PUBLIC_KEY_2_FP', rsa_public_key_2_fp, 'null', 'Fingerprint of user\'s second RSA public key.')
    ])

    actual = lambda_module.get_public_key_property(mock_conn, 'MY_USER', 'CURRENT_RSA_PUBLIC_KEY_FP')

    assert actual == expected
    mock_conn.cursor.assert_called_once()
    mock_cursor.execute.assert_called_once_with('DESC USER MY_USER')
