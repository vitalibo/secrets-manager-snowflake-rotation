import base64
import hashlib
import json
import logging
import os

import boto3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from snowflake import connector

logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', logging.INFO))


def handler(event, context):  # pylint: disable=unused-argument
    """
    Secrets Manager Snowflake Handler
    """

    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    service_client = boto3.client('secretsmanager')

    metadata = service_client.describe_secret(SecretId=arn)
    if 'RotationEnabled' in metadata and not metadata['RotationEnabled']:
        raise ValueError('Secret %s is not enabled for rotation' % arn)

    versions = metadata['VersionIdsToStages']
    if token not in versions:
        raise ValueError('Secret version %s has no stage for rotation of secret %s.' % (token, arn))

    if 'AWSCURRENT' in versions[token]:
        logger.info('Secret version %s already set as AWSCURRENT for secret %s.', token, arn)
        return

    elif 'AWSPENDING' not in versions[token]:
        raise ValueError('Secret version %s not set as AWSPENDING for rotation of secret %s.' % (token, arn))

    if step == 'createSecret':
        create_secret(service_client, arn, token)

    elif step == 'setSecret':
        set_secret(service_client, arn, token)

    elif step == 'testSecret':
        test_secret(service_client, arn, token)

    elif step == 'finishSecret':
        finish_secret(service_client, arn, token)

    else:
        raise ValueError('Invalid step parameter %s for secret %s' % (step, arn))


def create_secret(service_client, arn, token):
    """
    Generate a new key pair
    """

    current_dict = get_secret_dict(service_client, arn, 'AWSCURRENT')

    try:
        get_secret_dict(service_client, arn, 'AWSPENDING', token)
        logger.info('Successfully retrieved secret for %s.', arn)
    except service_client.exceptions.ResourceNotFoundException:
        private_key, public_key = generate_key_pair()

        current_dict['private_key'] = private_key
        current_dict['public_key'] = public_key

        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token,
                                        SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info('Successfully put secret for ARN %s and version %s.', arn, token)


def set_secret(service_client, arn, token):
    """
    Set the pending secret in the database
    """

    current_dict = get_secret_dict(service_client, arn, 'AWSCURRENT')
    pending_dict = get_secret_dict(service_client, arn, 'AWSPENDING', token)

    conn = get_connection(pending_dict)
    if conn:
        conn.close()
        logger.info('AWSPENDING secret is already set as RSA public key in Snowflake for secret arn %s.', arn)
        return

    if current_dict['user'] != pending_dict['user']:
        raise ValueError(
            'Attempting to modify user %s other than current user %s' % (
                pending_dict['user'], current_dict['user']))

    if current_dict['account'] != pending_dict['account']:
        raise ValueError(
            'Attempting to modify user for account %s other than current account %s' % (
                pending_dict['account'], current_dict['account']))

    master_arn = current_dict['masterarn']
    master_dict = get_secret_dict(service_client, master_arn, 'AWSCURRENT', None)

    if current_dict['account'] != master_dict['account']:
        raise ValueError(
            'Current Snowflake account %s is not the same account as master %s' % (
                current_dict['account'], master_dict['account']))

    conn = get_connection(master_dict, True)
    if not conn:
        raise ValueError('Unable to log into Snowflake using credentials in master secret %s' % master_arn)

    current_public_key_fp = calculate_public_key_fingerprint(current_dict['public_key'])
    property_name = get_public_key_property(conn, current_dict['user'], current_public_key_fp)

    try:
        sql_stmt = "ALTER USER %s SET %s='%s'" % (pending_dict['user'], property_name, pending_dict['public_key'])
        cur = conn.cursor()
        cur.execute(sql_stmt)
        logger.info('Successfully set RSA public key for user %s in Snowflake for secret arn %s.',
                    pending_dict['user'], arn)
    finally:
        conn.close()


def test_secret(service_client, arn, token):
    """
    Test the pending secret in the database
    """

    conn = get_connection(get_secret_dict(service_client, arn, 'AWSPENDING', token))
    if not conn:
        raise ValueError('Unable to log into database with pending secret of secret ARN %s' % arn)

    conn.close()
    logger.info('Successfully signed into Snowflake with AWSPENDING secret in %s.', arn)


def finish_secret(service_client, arn, token):
    """
    Finish the rotation by marking the pending secret as current
    """

    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata['VersionIdsToStages']:
        if 'AWSCURRENT' in metadata['VersionIdsToStages'][version]:
            if version == token:
                logger.info('Version %s already marked as AWSCURRENT for %s', version, arn)
                return
            current_version = version
            break

    service_client.update_secret_version_stage(SecretId=arn, VersionStage='AWSCURRENT', MoveToVersionId=token,
                                               RemoveFromVersionId=current_version)
    logger.info('Successfully set AWSCURRENT stage to version %s for secret %s.', token, arn)


def get_secret_dict(service_client, arn, stage, token=None):
    """
    Gets the secret dictionary corresponding for the secret arn, stage, and token
    """

    required_fields = ['account', 'user', 'private_key', 'public_key']

    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)

    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError('%s key is missing from secret JSON' % field)

    return secret_dict


def generate_key_pair():
    """
    Generate a new RSA key pair and return the private and public keys in base64 format
    """

    private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_key_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_obj = private_key_obj.public_key()
    public_key_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    def key_base64(key_pem, pem_type):
        return key_pem \
            .strip() \
            .removeprefix(f'-----BEGIN {pem_type} KEY-----') \
            .removesuffix(f'-----END {pem_type} KEY-----') \
            .replace('\n', '')

    private_key_b64 = key_base64(private_key_pem, pem_type='PRIVATE')
    public_key_b64 = key_base64(public_key_pem, pem_type='PUBLIC')
    return private_key_b64, public_key_b64


def get_connection(secret_dict, use_admin=False):
    """
    Get a connection to Snowflake using the provided secret dictionary.
    """

    try:
        kwargs = {
            'user': secret_dict['user'],
            'account': secret_dict['account'],
            'private_key': secret_dict['private_key'],
        }

        if use_admin:
            kwargs['role'] = 'ACCOUNTADMIN'

        return connector.connect(**kwargs)
    except connector.errors.Error as e:
        logger.warning('Unable to connect to Snowflake: %s', e)
        return None


def calculate_public_key_fingerprint(public_key_b64):
    """
    Calculate the SHA256 fingerprint of the public key in base64 format
    """

    der_bytes = base64.b64decode(public_key_b64)

    public_key = serialization.load_der_public_key(der_bytes)
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    sha256_digest = hashlib.sha256(der_bytes).digest()
    return base64.b64encode(sha256_digest).decode('utf-8')


def get_public_key_property(conn, user, rsa_public_key_fp):
    """
    Get free or unused Public Key property for a user
    """

    sql_stmt = f'DESC USER {user}'
    cur = conn.cursor()
    cur.execute(sql_stmt)

    properties = []
    for row in cur:
        if row[0] in ('RSA_PUBLIC_KEY_FP', 'RSA_PUBLIC_KEY_2_FP'):
            fingerprint = row[1].strip()[len('SHA256:'):]
            if not fingerprint:
                return row[0][:-3]
            if fingerprint != rsa_public_key_fp:
                properties.append(row[0][:-3])

    return properties[0]
