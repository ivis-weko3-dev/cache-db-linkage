from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from flask import current_app

from config import config, messages
from jc_redis.redis_conn import RedisConnection

def set_group_id(group_id):
    """Set group id to Redis

    Arguments:
        group_id(str): Group id
    """
    try:
        special_chars = config.GROUP_ID_SPECIAL_CHARS
        redis_connection = RedisConnection()
        store = redis_connection.connection(config.GROUPS_DB)
        # Register the system admin group ID
        if group_id == special_chars['sys_admin_group']:
            fqdn_list = [info['org_sp_fqdn'].replace('.', '_').replace('-', '_')
                        for info in config.SP_AUTHORIZATION_DICT.values()]
            rpush_flg = False
            for fqdn in fqdn_list:
                redis_key = fqdn + config.GAKUNIN_GROUP_SUFFIX
                binary_groups = store.lrange(redis_key, 0, -1)
                str_groups = [str(group, 'utf-8') for group in binary_groups]
                if group_id not in str_groups:
                    store.rpush(redis_key, group_id)
                    rpush_flg = True
            if rpush_flg:
                current_app.logger.info(messages.GROUP_ID_SET.format(group_id) )
                return
        else:
            if group_id.startswith(special_chars['prefix'])\
                and (special_chars['group_suffix'] in group_id or special_chars['role_suffix'] in group_id):
                # Register the group ID that follows the format
                if special_chars['group_suffix'] in group_id:
                    idx = group_id.index(special_chars['group_suffix'])
                    fqdn = group_id[len(special_chars['prefix']):idx]
                else:
                    idx = group_id.index(special_chars['role_suffix'])
                    fqdn = group_id[len(special_chars['prefix']):idx]
                redis_key = fqdn + config.GAKUNIN_GROUP_SUFFIX
                binary_groups = store.lrange(redis_key, 0, -1)
                str_groups = [str(group, 'utf-8') for group in binary_groups]
                if str_groups:
                    if group_id not in str_groups:
                        # Register the group ID that does not exist in the Redis
                        store.rpush(redis_key, group_id)
                    current_app.logger.info(messages.GROUP_ID_SET.format(group_id))
                    return
                else:
                    fqdn_list = [info['org_sp_fqdn'].replace('.', '_').replace('-', '_')
                                for info in config.SP_AUTHORIZATION_DICT.values()]
                    if fqdn in fqdn_list:
                        # Register the group ID that fqdn is in the SP_AUTHORIZATION_DICT
                        store.rpush(redis_key, group_id)
                        current_app.logger.info(messages.GROUP_ID_SET.format(group_id))
                        return
        # Not register the group ID that does not follow the format
        current_app.logger.info(messages.GROUP_ID_NOT_SET.format(group_id))
    except Exception as ex:
        raise ex

def validate_client_certificate(client_cert):
    """Validate client certificate

    Arguments:
        client_cert(str): Client certificate in PEM format

    Returns:
        str: Error message if validation fails, otherwise an empty string    
    """
    try:
        # Clean up the certificate data
        cleaned_cert = client_cert.strip()\
            .replace("\r", "")\
            .replace("\n", "")\
            .replace("-----BEGIN CERTIFICATE-----", "")\
            .replace("-----END CERTIFICATE-----", "")
        pem_cert = f"-----BEGIN CERTIFICATE-----\n{cleaned_cert}\n-----END CERTIFICATE-----"
        cert_data = pem_cert.encode("utf-8")
        
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Validate client certificate
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if subject_cn != config.TLS_CLIENT_CERT_CN:
            return messages.INVALID_CLIENT_CERTIFICATE.format(
                config.TLS_CLIENT_CERT_CN,
                subject_cn
            )
        return ''
    except Exception as ex:
        current_app.logger.error(f"Certificate validation failed: {ex}")
        return str(ex)
