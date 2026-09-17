"""Portable contract boundary/reference verifier, not a production collector.

Callers must independently authenticate sessions, atomically reserve nonces, check
freshness, authorize app/tenant, and validate Apple assertions. Valid MAC != human.
Legacy SDK uses a custom SHA256 MAC, explicitly NOT standard HMAC.
"""
import base64
import hashlib
import hmac
import json

class ContractError(ValueError):
    pass

UPLOAD_FIELDS = frozenset('kind contract_version app_id sdk_version report_id ts nonce session_token sig_ver key_id field_mapping_version device_id scene payload_json signature payload_sha256 attestation_key_id attestation_assertion trust_level re_attestation_assertion binding_mode binding_digest output_path_integrity'.split())

def _bytes(value):
    if not isinstance(value, str):
        raise ContractError('expected base64 string')
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ContractError('invalid base64') from exc

def _ms(value):
    # Explicit milliseconds domain: 2000-01-01 through 2100-01-01.
    if type(value) is not int or not 946684800000 <= value < 4102444800000:
        raise ContractError('timestamp must be Unix milliseconds (2000 <= year < 2100)')

def validate_upload(value, *, require_hardware=False):
    if not isinstance(value, dict) or value.get('kind') != 'sdk_report' or type(value.get('contract_version')) is not int or value['contract_version'] != 1:
        raise ContractError('expected sdk_report contract version 1')
    if set(value) - UPLOAD_FIELDS:
        raise ContractError('unknown upload fields; server aggregation is not client input')
    from .generated_contract import validate_shape
    try: validate_shape(value)
    except ValueError as exc: raise ContractError(str(exc)) from exc
    _ms(value.get('ts'))
    for field in ('app_id','sdk_version','report_id','nonce','session_token','sig_ver','key_id','device_id','scene','signature'):
        if not isinstance(value.get(field),str) or not value[field]:
            raise ContractError('missing string: '+field)
    for field in ('field_mapping_version','attestation_key_id','trust_level','binding_mode','binding_digest'):
        if field in value and not isinstance(value[field],str):
            raise ContractError('expected string: '+field)
    payload = _bytes(value.get('payload_json'))
    digest = _bytes(value.get('payload_sha256'))
    prefix = f"{len(value['nonce'].encode())}:{value['nonce']}|{value['ts']}|{len(value['report_id'].encode())}:{value['report_id']}|".encode()
    if not hmac.compare_digest(hashlib.sha256(prefix+payload).digest(),digest):
        raise ContractError('payload binding digest mismatch')
    for field in ('attestation_assertion','re_attestation_assertion'):
        if field in value: _bytes(value[field])
    if require_hardware and (not value.get('attestation_key_id') or not _bytes(value.get('attestation_assertion',''))):
        raise ContractError('attestation_incomplete')
    # Every inner field, including "server" / compact "sr", remains an untrusted
    # client claim. Never extract it as authenticated server aggregation.
    return dict(value)

def validate_business_event(value):
    if not isinstance(value, dict) or value.get('kind') != 'business_risk_event':
        raise ContractError('SDK reports are not business events')
    for field in ('occurred_at_ms','received_at_ms'): _ms(value.get(field))
    if not isinstance(value.get('event_id'),str) or not value['event_id']:
        raise ContractError('missing event_id')
    return dict(value)

def pseudonymize(key, *, tenant, app, domain, key_version, value):
    """Server-only standard HMAC; secret must never ship in SDK or Agent prompt."""
    if not isinstance(key,bytes) or len(key)<32:
        raise ContractError('server key must contain at least 32 bytes')
    parts=[tenant,app,domain,key_version,value]
    if any(not isinstance(x,str) or not x for x in parts):
        raise ContractError('identity namespace and value required')
    message=json.dumps(parts,ensure_ascii=False,separators=(',',':')).encode()
    return hmac.new(key,message,hashlib.sha256).hexdigest()

def legacy_mac(key,message):
    key=hashlib.sha256(key).digest() if len(key)>64 else key
    key=key.ljust(64,b'\x00')
    inner=hashlib.sha256(bytes(x^0x6D for x in key)+message).digest()
    return hashlib.sha256(bytes(x^0xA3 for x in key)+inner).hexdigest()

def canonical_payload(raw):
    """Validate JSON but return exact producer-signed UTF-8; never recanonicalize.

    The SDK serializes its canonical payload once into payload_json. Numbers,
    Unicode escape spelling and null are therefore interoperable byte-for-byte.
    """
    def reject_constant(_): raise ContractError('non-finite JSON number')
    def object_pairs(pairs):
        result={}
        for k,v in pairs:
            if k in result: raise ContractError('duplicate JSON key')
            result[k]=v
        return result
    try:
        text=raw.decode('utf-8')
        obj=json.loads(text,parse_constant=reject_constant,object_pairs_hook=object_pairs)
    except (UnicodeError, ValueError) as exc:
        raise ContractError('invalid JSON payload') from exc
    if not isinstance(obj,dict): raise ContractError('payload must be object')
    return text


def hkdf_sha256(ikm, salt, info, length=32):
    """RFC 5869 (standard HMAC, distinct from the legacy message MAC)."""
    if not 0 < length <= 255*32: raise ContractError('invalid HKDF length')
    prk=hmac.new(salt,ikm,hashlib.sha256).digest()
    out=b''; block=b''
    for counter in range(1,(length+31)//32+1):
        block=hmac.new(prk,block+info+bytes([counter]),hashlib.sha256).digest()
        out+=block
    return out[:length]


def derive_request_key(base_key, nonce, ts, emulator_flags=0):
    if type(emulator_flags) is not int or not 0 <= emulator_flags <= 0xffffffff:
        raise ContractError('invalid emulator flags')
    return hkdf_sha256(base_key,f'{nonce}|{ts}'.encode(),b'cprisk.report.hmac.v2h'+emulator_flags.to_bytes(4,'big'))


def verify_upload_with_base_key(upload, base_key, *, require_hardware=False):
    # Armor requires an independently authorized effective runtime key; callers
    # cannot use a static base key for that mode.
    try:
        value=validate_upload(upload,require_hardware=require_hardware)
        if value['sig_ver'] not in {'v1','v2','v2h','v3'}: return False
        key=derive_request_key(base_key,value['nonce'],value['ts']) if value['sig_ver']=='v2h' else base_key
        return verify_upload(value,key,require_hardware=require_hardware)
    except ContractError:
        return False

def signature_input(upload):
    fields=[upload['sig_ver'],upload['nonce'],str(upload['ts']),upload['session_token'],upload['report_id'],upload['key_id'],upload.get('field_mapping_version',''),upload.get('attestation_key_id','')]
    if upload['sig_ver']=='v3':
        fields.append(upload.get('trust_level',''))
        for name in ('attestation_assertion','re_attestation_assertion'):
            fields.append(hashlib.sha256(_bytes(upload[name])).hexdigest() if name in upload else '')
    fields.append(canonical_payload(_bytes(upload['payload_json'])))
    return '|'.join(fields).encode()

def verify_upload(upload,effective_key,*,require_hardware=False):
    """Validate transport and MAC with the already-derived request key.

    v2h caller supplies HKDF output; v2a supplies authorized armor request key.
    This function does NOT establish attestation trust, session validity, replay
    protection, app/scene binding or device identity, and is not an accept gate.
    """
    try:
        value=validate_upload(upload,require_hardware=require_hardware)
        if value['sig_ver'] not in {'v1','v2','v2h','v2a','v2d','v3'}:
            return False
        return hmac.compare_digest(legacy_mac(effective_key,signature_input(value)), value['signature'])
    except ContractError:
        return False
