"""Portable contract boundary/reference verifier, not a production collector.

Callers must independently authenticate sessions, atomically reserve nonces, check
freshness, authorize app/tenant, and validate Apple assertions. Valid MAC != human.

⚠️ CPRisk-MAC IS NOT STANDARD HMAC-SHA256 — DO NOT INTEROPERATE WITH STANDARD HMAC.
The legacy SDK message MAC (``legacy_cprisk_mac``) uses NON-STANDARD pads
(ipad=0x6D, opad=0xA3; standard HMAC-SHA256 uses 0x36/0x5C). Its output therefore
differs from ``hmac.new(key, message, hashlib.sha256)`` for the same key/message and
must NEVER be verified with a standard HMAC implementation. The non-standard pads
are preserved byte-for-byte for compatibility with the deployed server; silently
"fixing" them to the standard pads would break interop with every existing
deployment. Migration path: negotiate a contract/protocol version that uses
standard HMAC (e.g. ``pseudonymize`` / HKDF helpers here), do not silently change pads.
"""
import base64
import hashlib
import hmac
import json
import re

class ContractError(ValueError):
    pass

# Format/enum allow-lists for optional envelope fields (see validate_upload).
# trust_level: TrustLevel raw values in RiskDetectorApp (TrustChainManager.swift).
# Unknown trust levels are REJECTED (fail-closed); a future level needs a contract
# update, it must not be silently retained as trusted input.
_TRUST_LEVELS = frozenset({'hardware', 'derived', 'degraded'})
# binding_mode: union of ReportEnvelope (defaultBindingMode / isBindingModeCompatible)
# and GrpcReportPayload (signatureBindingMode) producer values.
_BINDING_MODES = frozenset({
    'hkdf_hmac_v1', 'plain_hmac_v1', 'plain_hmac_fallback_v1',
    'armor_request_binding_sha256_v1', 'self_reported_fields_bound_v3',
    'external_signature_provider_v1',
    'hkdf_derived_request_bound', 'armor_runtime_derived_request_bound',
    'degraded_base_key_request_bound', 'base_key_request_bound',
})
# field_mapping_version: server-owned mapping version label (e.g. "v1"); no spaces.
_FIELD_MAPPING_VERSION_RE = re.compile(r'\A[A-Za-z0-9._:-]{1,64}\Z')
# attestation_key_id: Apple App Attest key identifier (base64/base64url alphabet).
_ATTESTATION_KEY_ID_RE = re.compile(r'\A[A-Za-z0-9+/=_-]{1,256}\Z')
# binding_digest: lowercase hex SHA-256 of the signature input (ReportEnvelope.bindingDigestHex).
_BINDING_DIGEST_RE = re.compile(r'\A[0-9a-f]{64}\Z')

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
    # Format / enum validation (type-only checks are not enough: these fields
    # steer server trust decisions and mapping selection).
    if 'field_mapping_version' in value and not _FIELD_MAPPING_VERSION_RE.match(value['field_mapping_version']):
        raise ContractError('invalid field_mapping_version format')
    if 'attestation_key_id' in value and not _ATTESTATION_KEY_ID_RE.match(value['attestation_key_id']):
        raise ContractError('invalid attestation_key_id format')
    if 'trust_level' in value and value['trust_level'] not in _TRUST_LEVELS:
        raise ContractError('unknown trust_level rejected: '+value['trust_level'])
    if 'binding_mode' in value and value['binding_mode'] not in _BINDING_MODES:
        raise ContractError('unknown binding_mode rejected: '+value['binding_mode'])
    if 'binding_digest' in value and not _BINDING_DIGEST_RE.match(value['binding_digest']):
        raise ContractError('invalid binding_digest format (expected 64 lowercase hex)')
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

def legacy_cprisk_mac(key,message):
    """CPRisk-MAC: legacy SDK message MAC with NON-STANDARD pads (ipad=0x6D, opad=0xA3).

    NOT standard HMAC-SHA256 (pads 0x36/0x5C) and NOT interoperable with it.
    The pads are intentionally preserved for compatibility with the deployed
    server; see the module docstring. Migrate via contract/protocol version
    negotiation to standard HMAC — never by silently changing these pads.
    """
    key=hashlib.sha256(key).digest() if len(key)>64 else key
    key=key.ljust(64,b'\x00')
    inner=hashlib.sha256(bytes(x^0x6D for x in key)+message).digest()
    return hashlib.sha256(bytes(x^0xA3 for x in key)+inner).hexdigest()

def legacy_mac(key,message):
    """Deprecated alias for :func:`legacy_cprisk_mac` (kept for compatibility).

    The old name hid the fact that this is NOT standard HMAC. New code must
    call :func:`legacy_cprisk_mac` and must not verify its output with a
    standard HMAC implementation.
    """
    return legacy_cprisk_mac(key,message)

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
        return hmac.compare_digest(legacy_cprisk_mac(effective_key,signature_input(value)), value['signature'])
    except ContractError:
        return False
