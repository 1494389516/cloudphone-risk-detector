import base64, hashlib, json, unittest
from contracts import report_contract as c
from contracts.tests import test_contract

class WireCompletionTests(unittest.TestCase):
    def wire(self, raw):
        v=test_contract.ContractTests().upload(); v['sig_ver']='v2'
        v['payload_json']=base64.b64encode(raw).decode()
        v['payload_sha256']=base64.b64encode(hashlib.sha256(b'5:nonce|1790000000000|1:r|'+raw).digest()).decode()
        v['signature']=c.legacy_mac(b'k',b'v2|nonce|1790000000000|session|r|key||attest|'+raw)
        return v
    def test_exact_signed_float_unicode_null_bytes(self):
        raw='{"x":1e-7,"negative":-0.0,"text":"中😀","null":null,"bytes":"AP8="}'.encode()
        self.assertTrue(c.verify_upload(self.wire(raw),b'k'))
    def test_unknown_optional_type_fails(self):
        v=self.wire(b'{}'); v['output_path_integrity']={'x':7}
        with self.assertRaises(c.ContractError): c.validate_upload(v)
    def test_hkdf_rfc5869(self):
        self.assertEqual(c.hkdf_sha256(bytes.fromhex('0b'*22), bytes(range(13)), bytes(range(0xf0,0xfa)),42).hex(),'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
    def test_duplicate_and_nonfinite_rejected(self):
        for raw in [b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}']:
            self.assertFalse(c.verify_upload(self.wire(raw),b'k'))
    def test_base_key_wire_vectors_and_version_domains(self):
        import pathlib
        vectors=json.loads((pathlib.Path(__file__).parents[1]/'fixtures/wire_vectors.json').read_text())
        for vector in vectors:
            with self.subTest(vector=vector['name']):
                v=vector['upload']; key=bytes.fromhex(vector['base_key_hex'])
                self.assertTrue(c.verify_upload_with_base_key(v,key))
                self.assertEqual(c.signature_input(v).decode(),vector['signature_input'])
                altered=dict(v,sig_ver='v3' if v['sig_ver']!='v3' else 'v2')
                self.assertFalse(c.verify_upload_with_base_key(altered,key))
    def test_generator_is_current(self):
        import pathlib,subprocess,sys
        subprocess.run([sys.executable,str(pathlib.Path(__file__).parents[1]/'generate.py'),'--check'],check=True)
