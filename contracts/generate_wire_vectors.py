"""Regenerate deterministic raw-wire and HKDF vectors (test keys only)."""
import base64,hashlib,json,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from contracts.report_contract import derive_request_key,legacy_mac,signature_input
rows=[]
for version in ['v1','v2','v2h','v3']:
 for raw in ['{"deviceID":"device","scene":"login","x":1e-07,"z":-0.0}', '{"bytes":"AP8=","deviceID":"device","null":null,"scene":"login","unicode":"中😀"}']:
  payload=raw.encode();base_key=b'golden-base-key-0123456789'
  wire=dict(kind='sdk_report',contract_version=1,app_id='app',sdk_version='7',report_id='report',ts=1790000000000,nonce='nonce',session_token='session',sig_ver=version,key_id='key',device_id='device',scene='login',payload_json=base64.b64encode(payload).decode(),payload_sha256=base64.b64encode(hashlib.sha256(b'5:nonce|1790000000000|6:report|'+payload).digest()).decode(),signature='',trust_level='future_unknown',attestation_assertion='AP8=',re_attestation_assertion='AA==')
  key=derive_request_key(base_key,'nonce',wire['ts']) if version=='v2h' else base_key
  wire['signature']=legacy_mac(key,signature_input(wire))
  rows.append(dict(name=version+'-'+str(len(rows)),upload=wire,base_key_hex=base_key.hex(),effective_key_hex=key.hex(),signature_input=signature_input(wire).decode()))
(pathlib.Path(__file__).parent/'fixtures/wire_vectors.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
