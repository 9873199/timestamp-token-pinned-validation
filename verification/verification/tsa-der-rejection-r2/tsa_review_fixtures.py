"""Offline standards-based CMS fixtures. Generated private keys never leave memory."""
import datetime,hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from pyasn1.codec.der import encoder,decoder
from pyasn1.type import univ
from pyasn1_modules import rfc2315,rfc2459
import rfc3161ng as ts

UTC=datetime.timezone.utc
POLICY='1.3.6.1.4.1.55555.9.1'
CTYPE='1.2.840.113549.1.9.3'
MDIGEST='1.2.840.113549.1.9.4'
DATA=b'Generated archive acceptance sample\x00\xff'

def authority(*,eku='timestamp',eku_critical=True,ca=False,digital=True):
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Offline Generated TSA')])
 builder=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(3101).not_valid_before(datetime.datetime(2025,1,1,tzinfo=UTC)).not_valid_after(datetime.datetime(2030,1,1,tzinfo=UTC)).add_extension(x509.BasicConstraints(ca=ca,path_length=None),critical=True).add_extension(x509.KeyUsage(digital_signature=digital,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=False,decipher_only=False),critical=True)
 oids=[ExtendedKeyUsageOID.TIME_STAMPING] if eku=='timestamp' else [ExtendedKeyUsageOID.CODE_SIGNING] if eku=='other' else [ExtendedKeyUsageOID.TIME_STAMPING,ExtendedKeyUsageOID.CODE_SIGNING]
 cert=builder.add_extension(x509.ExtendedKeyUsage(oids),critical=eku_critical).sign(key,hashes.SHA256())
 return key,cert

def attribute(oid,values):
 a=rfc2315.Attribute();a['type']=univ.ObjectIdentifier(oid)
 for i,v in enumerate(values):a['values'][i]=univ.Any(v)
 return a

def make_token(authority_pair,*,hashname='sha256',mutation=None,nonce=98123,policy=POLICY,gentime='20261114120000Z'):
 key,cert=authority_pair;h=getattr(hashlib,hashname);hashclass=getattr(hashes,hashname.upper());digest=h(DATA).digest()
 info=ts.TSTInfo();info['version']=1;info['policy']=policy;info['messageImprint']['hashAlgorithm']['algorithm']=ts.get_hash_oid(hashname);info['messageImprint']['hashAlgorithm']['parameters']=univ.Null('');info['messageImprint']['hashedMessage']=digest;info['serialNumber']=8;info['genTime']=gentime
 if mutation!='nonce-missing':info['nonce']=nonce
 payload=encoder.encode(info)+(b'\x00' if mutation=='inner-trailing' else b'')
 attrs=[attribute(CTYPE,[encoder.encode(ts.id_ct_TSTInfo)]),attribute(MDIGEST,[encoder.encode(univ.OctetString(h(payload).digest()))])]
 if mutation=='missing-content-type':attrs=attrs[1:]
 if mutation=='missing-message-digest':attrs=attrs[:1]
 if mutation=='duplicate-content-type':attrs.append(attribute(CTYPE,[encoder.encode(ts.id_ct_TSTInfo)]))
 if mutation=='duplicate-message-digest':attrs.append(attribute(MDIGEST,[encoder.encode(univ.OctetString(h(payload).digest()))]))
 if mutation=='multi-content-type':attrs[0]=attribute(CTYPE,[encoder.encode(ts.id_ct_TSTInfo),encoder.encode(univ.ObjectIdentifier('1.2.840.113549.1.7.1'))])
 if mutation=='multi-message-digest':attrs[1]=attribute(MDIGEST,[encoder.encode(univ.OctetString(h(payload).digest())),encoder.encode(univ.OctetString(b'bad'))])
 if mutation=='wrong-content-type':attrs[0]=attribute(CTYPE,[encoder.encode(univ.ObjectIdentifier('1.2.840.113549.1.7.1'))])
 if mutation=='wrong-message-digest':attrs[1]=attribute(MDIGEST,[encoder.encode(univ.OctetString(b'\x00'*h().digest_size))])
 signed=univ.SetOf(componentType=rfc2315.Attribute())
 for a in attrs:signed.append(a)
 signed_bytes=encoder.encode(signed);signature=key.sign(signed_bytes,padding.PKCS1v15(),hashclass())
 # Independent cryptographic control, even for intentionally invalid CMS semantics.
 key.public_key().verify(signature,signed_bytes,padding.PKCS1v15(),hashclass())
 token=ts.TimeStampToken();token['contentType']=rfc2315.signedData;sd=token['content'];sd['version']=3;sd['digestAlgorithms'][0]['algorithm']=ts.get_hash_oid(hashname);sd['digestAlgorithms'][0]['parameters']=univ.Null('');sd['contentInfo']['contentType']=ts.id_ct_TSTInfo;sd['contentInfo']['content']=encoder.encode(univ.OctetString(payload))
 si=sd['signerInfos'][0];si['version']=1;parsed,rest=decoder.decode(cert.public_bytes(serialization.Encoding.DER),asn1Spec=rfc2459.Certificate());assert not rest
 si['issuerAndSerialNumber']['issuer']=parsed['tbsCertificate']['issuer'];si['issuerAndSerialNumber']['serialNumber']=cert.serial_number+(1 if mutation=='wrong-serial' else 0)
 si['digestAlgorithm']['algorithm']=ts.get_hash_oid(hashname);si['digestAlgorithm']['parameters']=univ.Null('');si['digestEncryptionAlgorithm']['algorithm']=univ.ObjectIdentifier('1.2.840.113549.1.1.1');si['digestEncryptionAlgorithm']['parameters']=univ.Null('')
 for i,a in enumerate(attrs):si['authenticatedAttributes'][i]=a
 si['encryptedDigest']=signature
 if mutation=='multiple-signers':sd['signerInfos'][1]=si
 if mutation=='wrong-envelope':token['contentType']=univ.ObjectIdentifier('1.2.840.113549.1.7.1')
 if mutation=='wrong-encapsulated-type':sd['contentInfo']['contentType']=univ.ObjectIdentifier('1.2.840.113549.1.7.1')
 der=encoder.encode(token)+(b'\x00' if mutation=='outer-trailing' else b'')
 return {'token':der,'certificate':cert.public_bytes(serialization.Encoding.PEM),'digest':digest,'hashname':hashname,'nonce':98123,'policy':POLICY,'independent_rsa_signature_control':True}

if __name__=='__main__':
 pair=authority()
 for alg in ['sha256','sha384','sha512']:
  x=make_token(pair,hashname=alg);assert ts.check_timestamp(x['token'],certificate=x['certificate'],digest=x['digest'],hashname=alg,nonce=x['nonce'])
  print(alg+': independently generated RSA CMS signature and original verifier positive control PASS')
 for mutation in ['missing-content-type','duplicate-content-type','duplicate-message-digest','multi-content-type','wrong-content-type','wrong-serial','multiple-signers','inner-trailing','outer-trailing']:
  x=make_token(pair,mutation=mutation);assert x['independent_rsa_signature_control'];print(mutation+': newly signed negative fixture constructed')
