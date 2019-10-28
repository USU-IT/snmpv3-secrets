import hashlib


PASSWORD_LEN = 1048576


def snmpv3_key_from_password(password, engineid, hash_type, hex_output=True):
    key = derive_intermediate_key(password, hash_type)
    localized_key = localize_intermediate_key(key, engineid, hash_type)
    if hex_output:
        return localized_key.hex()
    return localized_key


def get_hash_type(hashname):
    if hashname == "sha":
        return "sha1"
    return hashname


def derive_intermediate_key(password, hash_type):
    hash_type = get_hash_type(hash_type)
    password = password.encode()
    hash_type = hash_type
    key_hash = hashlib.new(hash_type)

    # we want to hash PASSWORD_LEN bytes of password, wrapping as needed
    for i in range(PASSWORD_LEN // len(password)):
        key_hash.update(password)

    key_hash.update(password[: PASSWORD_LEN % len(password)])

    key = key_hash.digest()
    return key


def localize_intermediate_key(intermediate_key, engineid, hash_type):
    # localize for the engineid
    hash_type = get_hash_type(hash_type)
    localized = hashlib.new(hash_type)

    if isinstance(engineid, str):
        engineid = bytes.fromhex(engineid.replace(":", ""))

    localized.update(intermediate_key)
    localized.update(engineid)
    localized.update(intermediate_key)

    return localized.digest()
