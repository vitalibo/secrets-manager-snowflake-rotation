import importlib
import os
import subprocess
import tempfile
from unittest import mock

import pytest

lambda_module = importlib.import_module('lambda')


def test_generate_key_pair():
    private_key, public_key = lambda_module.generate_key_pair()

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        private_key_pem = f'-----BEGIN PRIVATE KEY-----\n{private_key}\n-----END PRIVATE KEY-----\n'
        tmp_file.write(private_key_pem)

    try:
        cmd = f'openssl rsa -in {tmp_file.name} -pubout'
        process = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

        derived_public_key = (
            process.stdout.strip()
            .removeprefix('-----BEGIN PUBLIC KEY-----')
            .removesuffix('-----END PUBLIC KEY-----')
            .replace('\n', '')
        )

        assert derived_public_key == public_key
    finally:
        os.remove(tmp_file.name)


def test_calculate_public_key_fingerprint():
    public_key = \
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtC/9FsVadzKSINLr/XiB' \
        'Xov78gcKfTmRSMQZgRF0Zbc3kBxVzLdEqjFkU5hZRLdso35jW6+Db0hwv2sXYvHk' \
        'GpMfk1fSQdTgp9hyj+yXLV0VNSqfCLIA1Pma/ti2siirZYoJ3OKd3ecQ2YJguI6T' \
        'weTr3REX2k6IvOYUpUHlE6ayF0vAZ7+k4PkuGDvTcc++e/jrW7qnGSS4Tv3Ctiq8' \
        'xDHFi+/BQTPRK5JTn6PSk7zxRSwi9VSVzRxJPb4pqsnSzmZpd3e2U+pYqWqQGU7x' \
        'iKaH2sWqQgWt3ym1ee+q+VAEyFCWWffx43xDU4YdLD7Oadkr8hl2NDXspr1tVycw' \
        'SQIDAQAB'

    actual = lambda_module.calculate_public_key_fingerprint(public_key)

    assert actual == 'LZA+fUAlY+/ddCn8doeOlv63ltihKHvpDMKnIeNyv4A='


def test_get_connection():
    with mock.patch('lambda.connector') as mock_connector:
        mock_connect = mock.Mock()
        mock_connector.connect.return_value = mock_connect
        mock_connector.errors.Error = MockError
        secret_dict = {'user': 'smith', 'account': 'mycompany', 'private_key': '<private_key>'}

        _lambda = importlib.import_module('lambda')
        actual = _lambda.get_connection(secret_dict, use_admin=False)

        assert actual == mock_connect
        mock_connector.connect.assert_called_once_with(
            user='smith', account='mycompany', private_key='<private_key>')


def test_get_connection_with_admin():
    with mock.patch('lambda.connector') as mock_connector:
        mock_connect = mock.Mock()
        mock_connector.connect.return_value = mock_connect
        mock_connector.errors.Error = MockError
        secret_dict = {'user': 'smith', 'account': 'mycompany', 'private_key': '<private_key>'}

        _lambda = importlib.import_module('lambda')
        actual = _lambda.get_connection(secret_dict, use_admin=True)

        assert actual == mock_connect
        mock_connector.connect.assert_called_once_with(
            user='smith', account='mycompany', private_key='<private_key>', role='ACCOUNTADMIN')


def test_get_connection_none_if_exception():
    with mock.patch('lambda.connector') as mock_connector:
        mock_connector.connect.side_effect = MockError('Connection failed')
        mock_connector.errors.Error = MockError
        secret_dict = {'user': 'smith', 'account': 'mycompany', 'private_key': '<private_key>'}

        _lambda = importlib.import_module('lambda')
        actual = _lambda.get_connection(secret_dict, use_admin=False)

        assert actual is None
        mock_connector.connect.assert_called_once_with(
            user='smith', account='mycompany', private_key='<private_key>')


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

    _lambda = importlib.import_module('lambda')
    actual = _lambda.get_public_key_property(mock_conn, 'MY_USER', 'CURRENT_RSA_PUBLIC_KEY_FP')

    assert actual == expected
    mock_conn.cursor.assert_called_once()
    mock_cursor.execute.assert_called_once_with('DESC USER MY_USER')


class MockError(Exception):
    """
    Mock error class to simulate Snowflake connector errors
    """
