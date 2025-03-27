import importlib
from unittest import mock

import pytest


def test_get_connection():
    with mock.patch('lambda.connector') as mock_connector:
        mock_connect = mock.Mock()
        mock_connector.connect.return_value = mock_connect
        mock_connector.errors.Error = MockError
        secret_dict = {'user': 'smith', 'account': 'mycompany', 'private_key': '<private_key>'}

        _lambda = importlib.import_module('lambda')
        actual = _lambda.get_connection(secret_dict, use_admin=False)

        assert actual == mock_connect
        mock_connector.connect.assert_called_once_with(user='smith', account='mycompany', private_key='<private_key>')


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
        mock_connector.connect.assert_called_once_with(user='smith', account='mycompany', private_key='<private_key>')


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
