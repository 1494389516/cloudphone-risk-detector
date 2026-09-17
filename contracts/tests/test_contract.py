import base64
import copy
import hashlib
import json
import pathlib
import unittest
from contracts.report_contract import validate_upload, validate_business_event, pseudonymize, ContractError, verify_upload

class ContractTests(unittest.TestCase):
    def upload(self):
        payload = b'{"deviceID":"device","scene":"login"}'
        return dict(kind='sdk_report', contract_version=1, app_id='app', sdk_version='7', report_id='r', ts=1790000000000, nonce='nonce', session_token='session', sig_ver='v3', key_id='key', device_id='device', scene='login', payload_json=base64.b64encode(payload).decode(), signature='0'*64, payload_sha256=base64.b64encode(hashlib.sha256(b'5:nonce|1790000000000|1:r|'+payload).digest()).decode(), attestation_key_id='attest', attestation_assertion='YQ==', trust_level='hardware', re_attestation_assertion='Yg==')
    def test_lossless_upload(self):
        value=self.upload(); self.assertEqual(validate_upload(value), value)
    def test_unknown_trust_enum_preserved(self):
        value=self.upload(); value['trust_level']='future_level'; self.assertEqual(validate_upload(value)['trust_level'],'future_level')
    def test_timestamp_seconds_rejected(self):
        value=self.upload(); value['ts']=1790000000
        with self.assertRaises(ContractError): validate_upload(value)
    def test_business_event_not_report(self):
        with self.assertRaises(ContractError): validate_business_event(self.upload())
    def test_missing_assertion_for_server_required_attestation(self):
        value=self.upload(); del value['attestation_assertion']
        with self.assertRaises(ContractError): validate_upload(value, require_hardware=True)
    def test_client_cannot_supply_server_aggregation(self):
        value=self.upload(); value['server_features']={'ip_device_count':999}
        with self.assertRaises(ContractError): validate_upload(value)
    def test_identity_tenant_app_domain_key_isolation(self):
        key=b'x'*32
        values=[pseudonymize(key, tenant=t, app=a, domain=d, key_version=v, value='2001:db8::1') for t,a,d,v in [('a','app','ip','1'),('b','app','ip','1'),('a','other','ip','1'),('a','app','account','1'),('a','app','ip','2')]]
        self.assertEqual(len(set(values)),5)
    def test_vectors(self):
        path=pathlib.Path(__file__).parents[1]/'fixtures'/'report_vectors.json'
        for vector in json.loads(path.read_text()):
            with self.subTest(vector=vector['name']):
                self.assertTrue(verify_upload(vector['upload'], bytes.fromhex(vector['effective_key_hex'])))
                altered=copy.deepcopy(vector['upload']); altered['attestation_key_id']='changed'
                self.assertFalse(verify_upload(altered, bytes.fromhex(vector['effective_key_hex'])))
