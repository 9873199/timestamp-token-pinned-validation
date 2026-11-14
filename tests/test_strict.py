# Offline tests for rfc3161ng.check_timestamp_strict and the strict mode of
# RemoteTimestamper.  All certificates, keys and CMS tokens are generated
# locally in memory; no network access and no on-disk key material.
import datetime
import hashlib

import pytest

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, useful
from pyasn1_modules import rfc2459, rfc2315

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

import rfc3161ng
from rfc3161ng.api import (
    id_attribute_contentType,
    id_attribute_messageDigest,
    id_rsaEncryption,
    id_sha256WithRSAEncryption,
    id_sha384WithRSAEncryption,
    id_sha512WithRSAEncryption,
)

GEN_TIME = '20261114120000Z'
POLICY_OID = '1.2.3.4.5.6.7'
DATA = b'important archived document'
NONCE = 0x5EC0E7

RSA_OID_BY_HASH = {
    'sha256': id_sha256WithRSAEncryption,
    'sha384': id_sha384WithRSAEncryption,
    'sha512': id_sha512WithRSAEncryption,
}


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_certificate(key, common_name, *, ca=False, eku_oids=(ExtendedKeyUsageOID.TIME_STAMPING,),
                     eku_critical=True, key_usage=True, digital_signature=True,
                     not_before=datetime.datetime(2020, 1, 1),
                     not_after=datetime.datetime(2030, 1, 1), serial=None):
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'rfc3161ng test'),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = x509.CertificateBuilder(
        issuer_name=name,
        subject_name=name,
        public_key=key.public_key(),
        serial_number=serial if serial is not None else x509.random_serial_number(),
        not_valid_before=not_before,
        not_valid_after=not_after,
    )
    builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if eku_oids is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku_oids)), critical=eku_critical)
    return builder.sign(key, hashes.SHA256())


def pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def algorithm_identifier(oid):
    ai = rfc2459.AlgorithmIdentifier()
    ai.setComponentByPosition(0, univ.ObjectIdentifier(oid))
    return ai


def der_length(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def der_wrap(tag_byte, payload):
    return bytes([tag_byte]) + der_length(len(payload)) + payload


def der_unwrap(encoded):
    '''Return the content octets of a DER TLV.'''
    if encoded[1] & 0x80:
        header = 2 + (encoded[1] & 0x7F)
        length = int.from_bytes(encoded[2:header], 'big')
    else:
        header = 2
        length = encoded[1]
    assert len(encoded) - header == length
    return encoded[header:]


def make_attribute(oid, values):
    attribute = rfc2315.Attribute()
    attribute.setComponentByPosition(0, univ.ObjectIdentifier(oid))
    value_set = univ.SetOf()
    for i, value in enumerate(values):
        value_set.setComponentByPosition(i, value)
    attribute.setComponentByPosition(1, value_set)
    return attribute


def make_tst_info(digest, hashname, nonce=NONCE, policy=POLICY_OID, gen_time=GEN_TIME,
                  serial=1, imprint_hashname=None, imprint=None):
    tst_info = rfc3161ng.TSTInfo()
    tst_info.setComponentByPosition(0, 'v1')
    if policy is not None:
        tst_info.setComponentByPosition(1, univ.ObjectIdentifier(policy))
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByPosition(
        0, algorithm_identifier(rfc3161ng.get_hash_oid(imprint_hashname or hashname))
    )
    message_imprint.setComponentByPosition(
        1, univ.OctetString(digest if imprint is None else imprint)
    )
    tst_info.setComponentByPosition(2, message_imprint)
    tst_info.setComponentByPosition(3, serial)
    tst_info.setComponentByPosition(4, useful.GeneralizedTime(gen_time))
    if nonce is not None:
        tst_info.setComponentByPosition(7, nonce)
    return encoder.encode(tst_info)


def make_signer_info(signer_cert, signer_key, econtent, hashname, *,
                     signature_oid=None, attributes='default'):
    issuer, _ = decoder.decode(signer_cert.issuer.public_bytes(), asn1Spec=rfc2459.Name())
    issuer_and_serial = rfc2315.IssuerAndSerialNumber()
    issuer_and_serial.setComponentByName('issuer', issuer)
    issuer_and_serial.setComponentByName('serialNumber', signer_cert.serial_number)
    digest_algorithm = algorithm_identifier(rfc3161ng.get_hash_oid(hashname))
    if attributes == 'default':
        content_digest = hashlib.new(hashname, econtent).digest()
        attributes = [
            make_attribute(id_attribute_contentType, [univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)]),
            make_attribute(id_attribute_messageDigest, [univ.OctetString(content_digest)]),
        ]
    if attributes is not None:
        signed_attributes = rfc2315.Attributes()
        for i, attribute in enumerate(attributes):
            signed_attributes.setComponentByPosition(i, attribute)
        # DER of the SET OF attributes is the signature input; in the
        # SignerInfo only its content octets are stored, under the
        # implicit [0] tag
        attributes_der = encoder.encode(signed_attributes)
        signature_input = attributes_der
    else:
        attributes_der = None
        signature_input = econtent
    if signature_oid is None:
        signature_oid = RSA_OID_BY_HASH[hashname]
    signature = signer_key.sign(
        signature_input, padding.PKCS1v15(), getattr(hashes, hashname.upper())()
    )
    # assemble the SignerInfo DER manually so the implicitly tagged [0]
    # authenticatedAttributes come out exactly as on the wire
    signer_info_der = der_wrap(0x30, b''.join([
        encoder.encode(univ.Integer(1)),
        encoder.encode(issuer_and_serial),
        encoder.encode(digest_algorithm),
        der_wrap(0xA0, der_unwrap(attributes_der)) if attributes_der is not None else b'',
        encoder.encode(algorithm_identifier(signature_oid)),
        encoder.encode(univ.OctetString(signature)),
    ]))
    signer_info, substrate = decoder.decode(signer_info_der, asn1Spec=rfc2315.SignerInfo())
    assert not substrate
    return signer_info


def make_token(tsa_cert, tsa_key, digest, hashname='sha256', *,
               nonce=NONCE, policy=POLICY_OID, gen_time=GEN_TIME,
               imprint_hashname=None, imprint=None,
               signer_cert=None, signer_key=None, signature_oid=None,
               attributes='default', extra_signer=None, econtent_trailing=b''):
    '''Build a DER encoded TimeStampToken.  By default it is a fully valid
    token signed by the TSA key; keyword arguments introduce exactly one
    defect each while keeping the signature itself valid.'''
    tst_info_der = make_tst_info(
        digest, hashname, nonce=nonce, policy=policy, gen_time=gen_time,
        imprint_hashname=imprint_hashname, imprint=imprint,
    )
    econtent = tst_info_der + econtent_trailing

    content_info = rfc2315.ContentInfo()
    content_info.setComponentByPosition(0, rfc3161ng.id_ct_TSTInfo)
    content_info.setComponentByPosition(1, univ.OctetString(econtent))

    signed_data = rfc2315.SignedData()
    signed_data.setComponentByName('version', 1)
    digest_algorithms = rfc2315.DigestAlgorithmIdentifiers()
    digest_algorithms.setComponentByPosition(
        0, algorithm_identifier(rfc3161ng.get_hash_oid(hashname))
    )
    signed_data.setComponentByName('digestAlgorithms', digest_algorithms)
    signed_data.setComponentByName('contentInfo', content_info)

    signer_infos = rfc2315.SignerInfos()
    signer_infos.setComponentByPosition(0, make_signer_info(
        signer_cert or tsa_cert, signer_key or tsa_key, econtent, hashname,
        signature_oid=signature_oid, attributes=attributes,
    ))
    if extra_signer is not None:
        extra_cert, extra_key = extra_signer
        signer_infos.setComponentByPosition(1, make_signer_info(extra_cert, extra_key, econtent, hashname))
    signed_data.setComponentByName('signerInfos', signer_infos)

    # assemble the ContentInfo DER manually so the explicit [0] tag around
    # the SignedData comes out exactly as on the wire
    token_der = der_wrap(0x30, b''.join([
        encoder.encode(univ.ObjectIdentifier(rfc2315.signedData)),
        der_wrap(0xA0, encoder.encode(signed_data)),
    ]))
    token, substrate = decoder.decode(token_der, asn1Spec=rfc3161ng.TimeStampToken())
    assert not substrate
    return encoder.encode(token)


def make_response(token_der):
    token, _ = decoder.decode(token_der, asn1Spec=rfc3161ng.TimeStampToken())
    response = rfc3161ng.TimeStampResp()
    status = rfc3161ng.PKIStatusInfo()
    status.setComponentByPosition(0, 'granted')
    response.setComponentByPosition(0, status)
    response.setComponentByPosition(1, token)
    return encoder.encode(response)


@pytest.fixture(scope='module')
def tsa():
    key = make_key()
    return make_certificate(key, u'Test TSA'), key


@pytest.fixture(scope='module')
def digest():
    return hashlib.sha256(DATA).digest()


def strict_kwargs(_certificate, _digest, **overrides):
    kwargs = dict(
        certificate=pem(_certificate),
        digest=_digest,
        hashname='sha256',
        nonce=NONCE,
        policy=POLICY_OID,
    )
    kwargs.update(overrides)
    return kwargs


# -- positive control ---------------------------------------------------------

@pytest.mark.parametrize('hashname', ['sha256', 'sha384', 'sha512'])
def test_strict_valid_token_all_hashes(tsa, hashname):
    tsa_cert, tsa_key = tsa
    digest = hashlib.new(hashname, DATA).digest()
    token = make_token(tsa_cert, tsa_key, digest, hashname)
    assert rfc3161ng.check_timestamp_strict(
        token, **strict_kwargs(tsa_cert, digest, hashname=hashname)
    ) is True


def test_strict_valid_token_rsa_encryption_oid(tsa, digest):
    # rsaEncryption as signature OID (hash carried by digestAlgorithm only)
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, signature_oid=id_rsaEncryption)
    assert rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest)) is True


def test_strict_valid_token_without_nonce_and_policy(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, nonce=None, policy=None)
    assert rfc3161ng.check_timestamp_strict(
        token, certificate=pem(tsa_cert), digest=digest, hashname='sha256'
    ) is True


def test_strict_accepts_x509_certificate_object(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    assert rfc3161ng.check_timestamp_strict(
        token, **strict_kwargs(tsa_cert, digest, certificate=tsa_cert)
    ) is True


def test_legacy_check_timestamp_still_accepts_token(tsa, digest):
    # backward compatibility: the legacy, non-strict entry point is unchanged
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    assert rfc3161ng.check_timestamp(
        token, certificate=pem(tsa_cert), digest=digest, hashname='sha256', nonce=NONCE
    ) is True


# -- authorization failures: valid signature, wrong signer --------------------

def test_strict_rejects_resigned_by_attacker(tsa, digest):
    # The attacker re-signs the very same TSTInfo with their own, perfectly
    # valid TSA-looking certificate.  The signature verifies under the
    # attacker key, so rejection is about authorization, not corruption.
    tsa_cert, tsa_key = tsa
    attacker_key = make_key()
    attacker_cert = make_certificate(attacker_key, u'Attacker TSA')
    token = make_token(
        tsa_cert, tsa_key, digest,
        signer_cert=attacker_cert, signer_key=attacker_key,
    )
    # sanity: the legacy check trusts the attacker's certificate
    assert rfc3161ng.check_timestamp(
        token, certificate=pem(attacker_cert), digest=digest, hashname='sha256', nonce=NONCE
    ) is True
    with pytest.raises(ValueError, match='serial number'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_token_embedded_certificate(tsa, digest):
    # strict mode never falls back to certificates attached to the token
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    with pytest.raises(ValueError, match='pinned TSA certificate'):
        rfc3161ng.check_timestamp_strict(token, None, digest=digest, hashname='sha256')


# -- structural failures, all signed by the legitimate TSA key -----------------

def test_strict_rejects_two_signer_infos(tsa, digest):
    tsa_cert, tsa_key = tsa
    other_key = make_key()
    other_cert = make_certificate(other_key, u'Second TSA')
    token = make_token(tsa_cert, tsa_key, digest, extra_signer=(other_cert, other_key))
    with pytest.raises(ValueError, match='exactly one SignerInfo'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_missing_message_digest_attribute(tsa, digest):
    tsa_cert, tsa_key = tsa
    attributes = [
        make_attribute(id_attribute_contentType, [univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)]),
    ]
    token = make_token(tsa_cert, tsa_key, digest, attributes=attributes)
    with pytest.raises(ValueError, match='exactly one messageDigest'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_missing_content_type_attribute(tsa, digest):
    tsa_cert, tsa_key = tsa
    content_digest = hashlib.sha256(make_tst_info(digest, 'sha256')).digest()
    attributes = [
        make_attribute(id_attribute_messageDigest, [univ.OctetString(content_digest)]),
    ]
    token = make_token(tsa_cert, tsa_key, digest, attributes=attributes)
    with pytest.raises(ValueError, match='exactly one contentType'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_no_authenticated_attributes(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, attributes=None)
    with pytest.raises(ValueError, match='no authenticatedAttributes'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_duplicate_content_type_attribute(tsa, digest):
    tsa_cert, tsa_key = tsa
    content_digest = hashlib.sha256(make_tst_info(digest, 'sha256')).digest()
    attributes = [
        make_attribute(id_attribute_contentType, [univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)]),
        make_attribute(id_attribute_contentType, [univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)]),
        make_attribute(id_attribute_messageDigest, [univ.OctetString(content_digest)]),
    ]
    token = make_token(tsa_cert, tsa_key, digest, attributes=attributes)
    with pytest.raises(ValueError, match='exactly one contentType'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_multi_valued_message_digest(tsa, digest):
    tsa_cert, tsa_key = tsa
    content_digest = hashlib.sha256(make_tst_info(digest, 'sha256')).digest()
    attributes = [
        make_attribute(id_attribute_contentType, [univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)]),
        make_attribute(id_attribute_messageDigest, [
            univ.OctetString(content_digest),
            univ.OctetString(content_digest),
        ]),
    ]
    token = make_token(tsa_cert, tsa_key, digest, attributes=attributes)
    with pytest.raises(ValueError, match='single-valued'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_content_type_attribute(tsa, digest):
    tsa_cert, tsa_key = tsa
    content_digest = hashlib.sha256(make_tst_info(digest, 'sha256')).digest()
    attributes = [
        # id-data instead of id-ct-TSTInfo
        make_attribute(id_attribute_contentType, [univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 1))]),
        make_attribute(id_attribute_messageDigest, [univ.OctetString(content_digest)]),
    ]
    token = make_token(tsa_cert, tsa_key, digest, attributes=attributes)
    with pytest.raises(ValueError, match='not id-ct-TSTInfo'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_message_digest_attribute(tsa, digest):
    tsa_cert, tsa_key = tsa
    attributes = [
        make_attribute(id_attribute_contentType, [univ.ObjectIdentifier(rfc3161ng.id_ct_TSTInfo)]),
        make_attribute(id_attribute_messageDigest, [univ.OctetString(b'\x00' * 32)]),
    ]
    token = make_token(tsa_cert, tsa_key, digest, attributes=attributes)
    with pytest.raises(ValueError, match='does not match the encapsulated content'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_trailing_data_after_token(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    with pytest.raises(ValueError, match='trailing data'):
        rfc3161ng.check_timestamp_strict(token + b'\x05\x00', **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_trailing_data_inside_econtent(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, econtent_trailing=b'\x05\x00')
    with pytest.raises(ValueError, match='trailing data'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


# -- request binding failures ---------------------------------------------------

def test_strict_rejects_wrong_nonce(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, nonce=NONCE + 1)
    with pytest.raises(ValueError, match='nonce'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_missing_nonce(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, nonce=None)
    with pytest.raises(ValueError, match='nonce'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_imprint_algorithm(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, imprint_hashname='sha384',
                       imprint=hashlib.sha384(DATA).digest())
    with pytest.raises(ValueError, match='imprint algorithm'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_imprint_length(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, imprint=digest + b'\x00')
    with pytest.raises(ValueError, match='imprint length'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_imprint_value(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest,
                       imprint=hashlib.sha256(b'other data').digest())
    with pytest.raises(ValueError, match='imprint mismatch'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_policy(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, policy='1.2.3.4.5.6.8')
    with pytest.raises(ValueError, match='policy'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_missing_policy(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest, policy=None)
    with pytest.raises(ValueError, match='policy'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_wrong_digest_length_argument(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    with pytest.raises(ValueError, match='digest length'):
        rfc3161ng.check_timestamp_strict(
            token, **strict_kwargs(tsa_cert, digest, digest=digest[:-1])
        )


# -- signature algorithm failures ------------------------------------------------

def test_strict_rejects_sha1_signature(tsa, digest):
    tsa_cert, tsa_key = tsa
    # legitimately signed by the TSA key, but with sha1WithRSAEncryption
    token = make_token(
        tsa_cert, tsa_key, digest, hashname='sha1',
        imprint_hashname='sha256', imprint=digest,
        signature_oid=univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 5)),
    )
    with pytest.raises(ValueError, match='unsupported digest algorithm'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_unknown_signature_oid(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(
        tsa_cert, tsa_key, digest,
        signature_oid=univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 10)),  # RSASSA-PSS
    )
    with pytest.raises(ValueError, match='unsupported signature algorithm'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_inconsistent_signature_oid(tsa, digest):
    tsa_cert, tsa_key = tsa
    # digestAlgorithm says sha256 but signatureAlgorithm says sha512
    token = make_token(
        tsa_cert, tsa_key, digest, signature_oid=id_sha512WithRSAEncryption,
    )
    with pytest.raises(ValueError, match='inconsistent'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(tsa_cert, digest))


def test_strict_rejects_sha1_hashname(tsa, digest):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    with pytest.raises(ValueError, match='unsupported hash algorithm'):
        rfc3161ng.check_timestamp_strict(
            token, **strict_kwargs(tsa_cert, digest, hashname='sha1',
                                   digest=hashlib.sha1(DATA).digest())
        )


# -- certificate authorization failures -------------------------------------------

def test_strict_rejects_ca_certificate(tsa, digest):
    _, tsa_key = tsa
    ca_cert = make_certificate(tsa_key, u'Test CA', ca=True)
    token = make_token(ca_cert, tsa_key, digest)
    with pytest.raises(ValueError, match='CA certificate'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(ca_cert, digest))


def test_strict_rejects_missing_eku(tsa, digest):
    _, tsa_key = tsa
    cert = make_certificate(tsa_key, u'No EKU TSA', eku_oids=None)
    token = make_token(cert, tsa_key, digest)
    with pytest.raises(ValueError, match='no Extended Key Usage'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(cert, digest))


def test_strict_rejects_non_critical_eku(tsa, digest):
    _, tsa_key = tsa
    cert = make_certificate(tsa_key, u'Non-critical EKU TSA', eku_critical=False)
    token = make_token(cert, tsa_key, digest)
    with pytest.raises(ValueError, match='not critical'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(cert, digest))


def test_strict_rejects_extra_eku(tsa, digest):
    _, tsa_key = tsa
    cert = make_certificate(
        tsa_key, u'Extra EKU TSA',
        eku_oids=(ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.CLIENT_AUTH),
    )
    token = make_token(cert, tsa_key, digest)
    with pytest.raises(ValueError, match='only id-kp-timeStamping'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(cert, digest))


def test_strict_rejects_key_usage_without_digital_signature(tsa, digest):
    _, tsa_key = tsa
    cert = make_certificate(tsa_key, u'No digitalSignature TSA', digital_signature=False)
    token = make_token(cert, tsa_key, digest)
    with pytest.raises(ValueError, match='digitalSignature'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(cert, digest))


def test_strict_rejects_certificate_expired_at_gentime(tsa, digest):
    _, tsa_key = tsa
    cert = make_certificate(
        tsa_key, u'Expired TSA',
        not_before=datetime.datetime(2020, 1, 1),
        not_after=datetime.datetime(2021, 1, 1),
    )
    token = make_token(cert, tsa_key, digest)
    with pytest.raises(ValueError, match='not valid at genTime'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(cert, digest))


def test_strict_rejects_certificate_not_yet_valid_at_gentime(tsa, digest):
    _, tsa_key = tsa
    cert = make_certificate(
        tsa_key, u'Future TSA',
        not_before=datetime.datetime(2027, 1, 1),
        not_after=datetime.datetime(2030, 1, 1),
    )
    token = make_token(cert, tsa_key, digest)
    with pytest.raises(ValueError, match='not valid at genTime'):
        rfc3161ng.check_timestamp_strict(token, **strict_kwargs(cert, digest))


# -- RemoteTimestamper strict mode (offline, requests mocked) ---------------------

class FakeResponse(object):
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        pass


def test_remote_timestamper_strict(tsa, digest, monkeypatch):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    monkeypatch.setattr(
        'rfc3161ng.api.requests.post',
        lambda *args, **kwargs: FakeResponse(make_response(token)),
    )
    timestamper = rfc3161ng.RemoteTimestamper(
        'http://tsa.example.invalid/', certificate=pem(tsa_cert),
        hashname='sha256', tsa_policy_id=POLICY_OID, strict=True,
    )
    # return_tsr=True path goes through the same strict verification
    tsr = timestamper(data=DATA, nonce=NONCE, return_tsr=True)
    assert isinstance(tsr, rfc3161ng.TimeStampResp)
    # and so does the default path returning the token
    tst = timestamper(data=DATA, nonce=NONCE)
    assert isinstance(tst, bytes)


def test_remote_timestamper_strict_rejects_bad_token(tsa, digest, monkeypatch):
    tsa_cert, tsa_key = tsa
    attacker_key = make_key()
    attacker_cert = make_certificate(attacker_key, u'Attacker TSA')
    token = make_token(
        tsa_cert, tsa_key, digest,
        signer_cert=attacker_cert, signer_key=attacker_key,
    )
    monkeypatch.setattr(
        'rfc3161ng.api.requests.post',
        lambda *args, **kwargs: FakeResponse(make_response(token)),
    )
    timestamper = rfc3161ng.RemoteTimestamper(
        'http://tsa.example.invalid/', certificate=pem(tsa_cert),
        hashname='sha256', tsa_policy_id=POLICY_OID, strict=True,
    )
    with pytest.raises(ValueError, match='serial number'):
        timestamper(data=DATA, nonce=NONCE, return_tsr=True)


def test_remote_timestamper_strict_requires_certificate():
    timestamper = rfc3161ng.RemoteTimestamper('http://tsa.example.invalid/', strict=True)
    with pytest.raises(rfc3161ng.TimestampingError, match='pinned TSA certificate'):
        timestamper.check_response(rfc3161ng.TimeStampResp(), digest=b'\x00' * 32)


def test_remote_timestamper_legacy_mode_unchanged(tsa, digest, monkeypatch):
    tsa_cert, tsa_key = tsa
    token = make_token(tsa_cert, tsa_key, digest)
    monkeypatch.setattr(
        'rfc3161ng.api.requests.post',
        lambda *args, **kwargs: FakeResponse(make_response(token)),
    )
    # no certificate configured: legacy mode returns the token unchecked
    timestamper = rfc3161ng.RemoteTimestamper('http://tsa.example.invalid/', hashname='sha256')
    tsr = timestamper(data=DATA, nonce=NONCE, return_tsr=True)
    assert isinstance(tsr, rfc3161ng.TimeStampResp)
