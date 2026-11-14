"""Independent offline TSA contract checks; keys remain only in memory."""
import hashlib,json
import pytest
from pyasn1.codec.der import encoder,decoder
from pyasn1.type import univ
from pyasn1_modules import rfc2315
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import rfc3161ng as ts
import rfc3161ng.api as api
from tsa_review_fixtures import authority,make_token,DATA,POLICY,CTYPE
OTHER='1.3.6.1.4.1.55555.9.2'
@pytest.fixture(scope='module')
def pair(): return authority()
def verify(x,**overrides):
    kw=dict(certificate=x['certificate'],digest=x['digest'],hashname=x['hashname'],nonce=x['nonce'],policy=x['policy']);kw.update(overrides)
    return ts.check_timestamp_strict(x['token'],**kw)
def response(x):
    token,rest=decoder.decode(x['token'],asn1Spec=ts.TimeStampToken());assert not rest
    r=ts.TimeStampResp();r['status']['status']='granted';r['timeStampToken']=token
    return encoder.encode(r)
def install(monkeypatch,x,suffix=b''):
    seen=[]
    class Reply:
        content=response(x)+suffix
        def raise_for_status(self): pass
    def post(url,**kw):
        req=ts.decode_timestamp_request(kw['data']);seen.append(str(req['reqPolicy']) if req['reqPolicy'].isValue else None)
        return Reply()
    monkeypatch.setattr(api.requests,'post',post)
    return seen
@pytest.mark.parametrize('alg',['sha256','sha384','sha512'])
@pytest.mark.parametrize('use_data',[False,True])
def test_positive(pair,alg,use_data):
    x=make_token(pair,hashname=alg);assert x['independent_rsa_signature_control']
    assert verify(x,**({'digest':None,'data':DATA} if use_data else {})) is True
@pytest.mark.parametrize('mutation',['nonce-missing','inner-trailing','missing-content-type','missing-message-digest','duplicate-content-type','duplicate-message-digest','multi-content-type','multi-message-digest','wrong-content-type','wrong-message-digest','wrong-serial','multiple-signers','wrong-envelope','wrong-encapsulated-type','outer-trailing'])
def test_resigned_negative(pair,mutation):
    x=make_token(pair,mutation=mutation);assert x['independent_rsa_signature_control']
    with pytest.raises(ValueError): verify(x)
@pytest.mark.parametrize('options',[{'eku':'other'},{'eku':'both'},{'eku_critical':False},{'ca':True},{'digital':False}])
def test_certificate_authorization(options):
    x=make_token(authority(**options))
    with pytest.raises(ValueError): verify(x)
@pytest.mark.parametrize('when',['20240101000000Z','20310101000000Z'])
def test_time_authorization(pair,when):
    x=make_token(pair,gentime=when)
    with pytest.raises(ValueError): verify(x)
@pytest.mark.parametrize('overrides',[{'nonce':98124},{'digest':b'x'*32},{'digest':b'x'*31},{'hashname':'sha384','digest':b'x'*48},{'policy':OTHER},{'hashname':'sha1','digest':b'x'*20}])
def test_request_binding(pair,overrides):
    with pytest.raises(ValueError): verify(make_token(pair),**overrides)
def test_untrusted_key(pair):
    x=make_token(pair);other=make_token(authority())
    with pytest.raises(ValueError): verify(x,certificate=other['certificate'])
@pytest.mark.parametrize('mutation',['octet-trailing','attribute-trailing','pss','digest-signature-mismatch','imprint-length'])
def test_additional_der_and_algorithms(pair,mutation):
    x=make_token(pair);t,rest=decoder.decode(x['token'],asn1Spec=ts.TimeStampToken());assert not rest
    si=t['content']['signerInfos'][0]
    if mutation=='octet-trailing':
        t['content']['contentInfo']['content']=bytes(t['content']['contentInfo']['content'])+b'\x00'
    elif mutation=='attribute-trailing':
        for attr in si['authenticatedAttributes']:
            if str(attr['type'])==CTYPE: attr['values'][0]=univ.Any(bytes(attr['values'][0])+b'\x00')
        attrs=univ.SetOf(componentType=rfc2315.Attribute())
        for attr in si['authenticatedAttributes']: attrs.append(attr)
        signed=encoder.encode(attrs);sig=pair[0].sign(signed,padding.PKCS1v15(),hashes.SHA256());pair[0].public_key().verify(sig,signed,padding.PKCS1v15(),hashes.SHA256());si['encryptedDigest']=sig
    elif mutation=='pss': si['digestEncryptionAlgorithm']['algorithm']='1.2.840.113549.1.1.10'
    elif mutation=='digest-signature-mismatch': si['digestEncryptionAlgorithm']['algorithm']='1.2.840.113549.1.1.13'
    else:
        content,_=decoder.decode(bytes(t['content']['contentInfo']['content']),asn1Spec=univ.OctetString());info,_=decoder.decode(bytes(content),asn1Spec=ts.TSTInfo());info['messageImprint']['hashedMessage']=b'x'*31
        payload=encoder.encode(info);t['content']['contentInfo']['content']=encoder.encode(univ.OctetString(payload))
        for attr in si['authenticatedAttributes']:
            if str(attr['type'])=='1.2.840.113549.1.9.4': attr['values'][0]=univ.Any(encoder.encode(univ.OctetString(hashlib.sha256(payload).digest())))
        attrs=univ.SetOf(componentType=rfc2315.Attribute())
        for attr in si['authenticatedAttributes']: attrs.append(attr)
        signed=encoder.encode(attrs);sig=pair[0].sign(signed,padding.PKCS1v15(),hashes.SHA256());pair[0].public_key().verify(sig,signed,padding.PKCS1v15(),hashes.SHA256());si['encryptedDigest']=sig
    x['token']=encoder.encode(t)
    with pytest.raises(ValueError): verify(x)
@pytest.mark.parametrize('return_tsr',[False,True])
def test_remote_constructor_policy_control(pair,monkeypatch,return_tsr):
    x=make_token(pair);seen=install(monkeypatch,x)
    c=ts.RemoteTimestamper('https://offline.invalid/',certificate=x['certificate'],strict=True,tsa_policy_id=POLICY)
    result=c(data=DATA,nonce=x['nonce'],return_tsr=return_tsr);assert result is not None;assert seen==[POLICY]
@pytest.mark.parametrize('return_tsr',[False,True])
def test_remote_call_override_correct_token(pair,monkeypatch,return_tsr):
    x=make_token(pair,policy=OTHER);seen=install(monkeypatch,x)
    c=ts.RemoteTimestamper('https://offline.invalid/',certificate=x['certificate'],strict=True)
    assert c(data=DATA,nonce=x['nonce'],tsa_policy_id=OTHER,return_tsr=return_tsr) is not None
    assert seen==[OTHER]
@pytest.mark.parametrize('return_tsr',[False,True])
@pytest.mark.parametrize('constructor_policy',[None,POLICY])
def test_remote_call_override_mismatch_rejected(pair,monkeypatch,return_tsr,constructor_policy):
    x=make_token(pair,policy=POLICY);seen=install(monkeypatch,x)
    with pytest.raises(ValueError): verify(x,policy=OTHER)
    c=ts.RemoteTimestamper('https://offline.invalid/',certificate=x['certificate'],strict=True,tsa_policy_id=constructor_policy)
    accepted=False
    try: c(data=DATA,nonce=x['nonce'],tsa_policy_id=OTHER,return_tsr=return_tsr);accepted=True
    except ValueError: pass
    assert seen==[OTHER]
    print('POLICY_BINDING '+json.dumps({'constructor_policy':constructor_policy,'request_policy':seen[0],'signed_token_policy':POLICY,'return_tsr':return_tsr,'accepted':accepted,'rsa_signature_control':x['independent_rsa_signature_control']}))
    assert not accepted,'Signed token policy differs from actual per-call request'
@pytest.mark.parametrize('return_tsr',[False,True])
def test_remote_response_trailing_rejected(pair,monkeypatch,return_tsr):
    x=make_token(pair);install(monkeypatch,x,b'\x00')
    c=ts.RemoteTimestamper('https://offline.invalid/',certificate=x['certificate'],strict=True,tsa_policy_id=POLICY)
    with pytest.raises(ValueError): c(data=DATA,nonce=x['nonce'],return_tsr=return_tsr)
def test_legacy_compatibility(pair):
    x=make_token(pair);assert ts.check_timestamp(x['token'],certificate=x['certificate'],digest=x['digest'],hashname='sha256',nonce=x['nonce'])
