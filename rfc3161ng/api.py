import hashlib
import requests
import base64
import re
import datetime
import dateutil.relativedelta
import dateutil.tz

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459, rfc2315
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

import rfc3161ng

__all__ = (
    'RemoteTimestamper', 'check_timestamp', 'check_timestamp_strict', 'get_hash_oid',
    'TimestampingError', 'get_timestamp', 'make_timestamp_request',
    'encode_timestamp_request', 'encode_timestamp_response',
    'decode_timestamp_request', 'decode_timestamp_response',
)

id_attribute_contentType = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 3))
id_attribute_messageDigest = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))

id_rsaEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 1))
id_sha256WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 11))
id_sha384WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 12))
id_sha512WithRSAEncryption = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 1, 13))

#: Hash algorithms accepted by strict verification, both for the message
#: imprint and for the CMS signature.
STRICT_HASHNAMES = ('sha256', 'sha384', 'sha512')

#: Signature algorithms accepted by strict verification: RSA PKCS#1 v1.5
#: combined with one of the STRICT_HASHNAMES digests.  The value is the
#: digest the signature algorithm implies, or None when the digest is
#: carried solely by the SignerInfo digestAlgorithm field (rsaEncryption).
RSA_PKCS1V15_SIGNATURE_ALGORITHMS = {
    id_rsaEncryption: None,
    id_sha256WithRSAEncryption: 'sha256',
    id_sha384WithRSAEncryption: 'sha384',
    id_sha512WithRSAEncryption: 'sha512',
}


def get_hash_oid(hashname):
    return rfc3161ng.__dict__['id_' + hashname]


def get_hash_from_oid(oid):
    h = rfc3161ng.oid_to_hash.get(oid)
    if h is None:
        raise ValueError('unsupported hash algorithm', oid)
    return h


def get_hash_class_from_oid(oid):
    h = get_hash_from_oid(oid)
    return getattr(hashlib, h)


class TimestampingError(RuntimeError):
    pass


def generalizedtime_to_utc_datetime(gt, naive=True):
    m = re.match(r'(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})(?:(?P<minutes>\d{2})(?:(?P<seconds>\d{2})(?:[.,](?P<fractions>\d*))?)?)?(?P<tz>Z|[+-]\d{2}(?:\d{2})?)?', gt)
    if not m:
        raise ValueError("not an ASN.1 generalizedTime: '%s'" % (gt,))

    d = m.groupdict()
    dt = datetime.datetime(
        int(d['year']),
        int(d['month']),
        int(d['day']),
        int(d['hour']),
        int(d['minutes'] or 0),
        int(d['seconds'] or 0),
        int(float('0.' + d['fractions']) * 1000000 if d['fractions'] else 0)
    )
    if naive:
        if d['tz'] and d['tz'][0] in ('+', '-'):
            diff = dateutil.relativedelta.relativedelta(
                hours=int(d['tz'][1:3]),
                minutes=int(d['tz'][3:5]) if len(d['tz']) > 3 else 0
            )
            if d['tz'][0] == '+':
                dt -= diff
            else:
                dt += diff
        return dt

    if d['tz'] and re.match(r'^[+\-]\d*[^0]\d*$', d['tz']):
        diff = datetime.timedelta(
            hours=int(d['tz'][1:3]),
            minutes=int(d['tz'][3:5]) if len(d['tz']) > 3 else 0
        ).total_seconds()
        name = d['tz'][0:3]
        if len(d['tz']) > 3:
            name += ':' + d['tz'][3:5]
        dt = dt.replace(tzinfo=dateutil.tz.tzoffset(name, diff if d['tz'][0] == '+' else -diff))
    else:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())

    return dt


def get_timestamp(tst, naive=True):
    try:
        if not isinstance(tst, rfc3161ng.TimeStampToken):
            tst, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())
            if substrate:
                raise ValueError("extra data after tst")

        tstinfo = tst.getComponentByName('content').getComponentByPosition(2).getComponentByPosition(1)
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=univ.OctetString())
        if substrate:
            raise ValueError("extra data after tst")
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=rfc3161ng.TSTInfo())
        if substrate:
            raise ValueError("extra data after tst")
        genTime = tstinfo.getComponentByName('genTime')
        return generalizedtime_to_utc_datetime(str(genTime), naive)
    except PyAsn1Error as exc:
        raise ValueError('not a valid TimeStampToken', exc)


def load_certificate(signed_data, certificate=b""):
    backend = default_backend()

    if certificate == b"":
        try:
            certificate = signed_data['certificates'][0][0]
        except (KeyError, IndexError, TypeError):
            raise AttributeError("missing certificate")
        data = encoder.encode(certificate)
        return x509.load_der_x509_certificate(data, backend)

    if b'-----BEGIN CERTIFICATE-----' in certificate:
        return x509.load_pem_x509_certificate(certificate, backend)
    return x509.load_der_x509_certificate(certificate, backend)


def check_timestamp(tst, certificate=None, data=None, digest=None, hashname=None, nonce=None):
    hashname = hashname or 'sha1'
    hashobj = hashlib.new(hashname)
    if digest is None:
        if not data:
            raise ValueError("check_timestamp requires data or digest argument")
        hashobj.update(data)
        digest = hashobj.digest()

    if not isinstance(tst, rfc3161ng.TimeStampToken):
        tst, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())
        if substrate:
            raise ValueError("extra data after tst")
    signed_data = tst.content
    certificate = load_certificate(signed_data, certificate)
    if nonce is not None and int(tst.tst_info['nonce']) != int(nonce):
        raise ValueError('nonce is different or missing')
    # check message imprint with respect to locally computed digest
    message_imprint = tst.tst_info.message_imprint
    if message_imprint.hash_algorithm[0] != get_hash_oid(hashname) or bytes(message_imprint.hashed_message) != digest:
        raise ValueError('Message imprint mismatch')
    if not len(signed_data['signerInfos']):
        raise ValueError('No signature')
    # We validate only one signature
    signer_info = signed_data['signerInfos'][0]
    # check content type
    if tst.content['contentInfo']['contentType'] != rfc3161ng.id_ct_TSTInfo:
        raise ValueError("Signed content type is wrong: %s != %s" % (
            tst.content['contentInfo']['contentType'], rfc3161ng.id_ct_TSTInfo
        ))

    # check signed data digest
    content = bytes(decoder.decode(bytes(tst.content['contentInfo']['content']), asn1Spec=univ.OctetString())[0])
    # if there is authenticated attributes, they must contain the message
    # digest and they are the signed data otherwise the content is the
    # signed data
    if len(signer_info['authenticatedAttributes']):
        authenticated_attributes = signer_info['authenticatedAttributes']
        signer_digest_algorithm = signer_info['digestAlgorithm']['algorithm']
        signer_hash_class = get_hash_class_from_oid(signer_digest_algorithm)
        signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        content_digest = signer_hash_class(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = bytes(decoder.decode(bytes(authenticated_attribute[1][0]), asn1Spec=univ.OctetString())[0])
                    if signed_digest != content_digest:
                        raise ValueError('Content digest != signed digest')
                    s = univ.SetOf()
                    for i, x in enumerate(authenticated_attributes):
                        s.setComponentByPosition(i, x)
                    signed_data = encoder.encode(s)
                    break
                except PyAsn1Error:
                    raise
        else:
            raise ValueError('No signed digest')
    else:
        signed_data = content
    # check signature
    signature = signer_info['encryptedDigest']
    public_key = certificate.public_key()
    hash_family = getattr(hashes, signer_hash_name.upper())
    public_key.verify(
        bytes(signature),
        signed_data,
        padding.PKCS1v15(),
        hash_family(),
    )
    return True


def _decode_fully(data, asn1_spec, description):
    '''Decode one DER object and require the input to be fully consumed.'''
    value, substrate = decoder.decode(data, asn1Spec=asn1_spec)
    if substrate:
        raise ValueError('trailing data after %s' % description)
    return value


def _load_pinned_certificate(certificate):
    if isinstance(certificate, x509.Certificate):
        return certificate
    if not certificate:
        raise ValueError('strict verification requires a pinned TSA certificate')
    return load_certificate(None, certificate)


def _check_tsa_certificate(certificate, gen_time):
    '''Check that the pinned certificate was a legitimate TSA signer at gen_time.'''
    try:
        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc
    except AttributeError:
        not_valid_before = certificate.not_valid_before.replace(tzinfo=dateutil.tz.tzutc())
        not_valid_after = certificate.not_valid_after.replace(tzinfo=dateutil.tz.tzutc())
    if not not_valid_before <= gen_time <= not_valid_after:
        raise ValueError('TSA certificate is not valid at genTime %s' % gen_time)
    try:
        eku = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        raise ValueError('TSA certificate has no Extended Key Usage extension')
    if not eku.critical:
        raise ValueError('TSA certificate Extended Key Usage is not critical')
    if list(eku.value) != [x509.ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError('TSA certificate Extended Key Usage must contain only id-kp-timeStamping')
    try:
        key_usage = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        pass
    else:
        if not key_usage.digital_signature:
            raise ValueError('TSA certificate Key Usage does not allow digitalSignature')
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        pass
    else:
        if basic_constraints.ca:
            raise ValueError('TSA certificate must not be a CA certificate')


def _check_signer_identity(signer_info, certificate):
    '''Bind the SignerInfo issuerAndSerialNumber to the pinned certificate.'''
    if int(signer_info['version']) != 1:
        raise ValueError('unsupported SignerInfo version: %s' % signer_info['version'])
    issuer_and_serial = signer_info['issuerAndSerialNumber']
    if int(issuer_and_serial['serialNumber']) != certificate.serial_number:
        raise ValueError('signer serial number does not match the pinned TSA certificate')
    if encoder.encode(issuer_and_serial['issuer']) != certificate.issuer.public_bytes():
        raise ValueError('signer issuer does not match the pinned TSA certificate')


def _get_signature_hash(signer_info, certificate):
    '''Return the hash name for the CMS signature, rejecting anything but
    RSA PKCS#1 v1.5 with SHA-256/384/512.'''
    digest_algorithm = signer_info['digestAlgorithm']['algorithm']
    try:
        signer_hashname = get_hash_from_oid(digest_algorithm)
    except ValueError:
        raise ValueError('unsupported digest algorithm: %s' % digest_algorithm)
    if signer_hashname not in STRICT_HASHNAMES:
        raise ValueError('unsupported digest algorithm for strict verification: %s' % signer_hashname)
    signature_algorithm = signer_info['digestEncryptionAlgorithm']['algorithm']
    if signature_algorithm not in RSA_PKCS1V15_SIGNATURE_ALGORITHMS:
        raise ValueError(
            'unsupported signature algorithm: %s '
            '(only RSA PKCS#1 v1.5 with SHA-256/384/512 is accepted)' % signature_algorithm
        )
    implied_hashname = RSA_PKCS1V15_SIGNATURE_ALGORITHMS[signature_algorithm]
    if implied_hashname is not None and implied_hashname != signer_hashname:
        raise ValueError(
            'digestAlgorithm %s is inconsistent with signatureAlgorithm %s' % (
                digest_algorithm, signature_algorithm
            )
        )
    if not isinstance(certificate.public_key(), rsa.RSAPublicKey):
        raise ValueError('pinned TSA certificate does not carry an RSA public key')
    return signer_hashname


def _check_authenticated_attributes(signer_info, content, signer_hashname):
    '''Check the signed attributes and return their DER encoding, which is
    the actual signature input.

    Exactly one single-valued contentType attribute matching id-ct-TSTInfo
    and exactly one single-valued messageDigest attribute matching the
    encapsulated content are required.'''
    authenticated_attributes = signer_info['authenticatedAttributes']
    if not authenticated_attributes.isValue or not len(authenticated_attributes):
        raise ValueError('SignerInfo carries no authenticatedAttributes')
    content_type_attributes = []
    message_digest_attributes = []
    for attribute in authenticated_attributes:
        if attribute[0] == id_attribute_contentType:
            content_type_attributes.append(attribute)
        elif attribute[0] == id_attribute_messageDigest:
            message_digest_attributes.append(attribute)
    if len(content_type_attributes) != 1:
        raise ValueError(
            'expected exactly one contentType attribute, got %d' % len(content_type_attributes)
        )
    if len(message_digest_attributes) != 1:
        raise ValueError(
            'expected exactly one messageDigest attribute, got %d' % len(message_digest_attributes)
        )
    content_type_values = content_type_attributes[0][1]
    if len(content_type_values) != 1:
        raise ValueError('contentType attribute must be single-valued')
    content_type = _decode_fully(
        bytes(content_type_values[0]), univ.ObjectIdentifier(), 'contentType attribute'
    )
    if content_type != rfc3161ng.id_ct_TSTInfo:
        raise ValueError('contentType attribute is not id-ct-TSTInfo: %s' % content_type)
    message_digest_values = message_digest_attributes[0][1]
    if len(message_digest_values) != 1:
        raise ValueError('messageDigest attribute must be single-valued')
    message_digest = _decode_fully(
        bytes(message_digest_values[0]), univ.OctetString(), 'messageDigest attribute'
    )
    content_digest = hashlib.new(signer_hashname, content).digest()
    if bytes(message_digest) != content_digest:
        raise ValueError('messageDigest attribute does not match the encapsulated content')
    signed_attributes = univ.SetOf()
    for i, attribute in enumerate(authenticated_attributes):
        signed_attributes.setComponentByPosition(i, attribute)
    return encoder.encode(signed_attributes)


def check_timestamp_strict(tst, certificate, data=None, digest=None, hashname='sha256', nonce=None, policy=None):
    '''Strictly verify a TimeStampToken against a pinned TSA certificate.

    Unlike :func:`check_timestamp`, this does not only check that some
    signature verifies: it binds the token to the caller-supplied TSA
    certificate, the request parameters and the TSTInfo structure.

    The following is enforced:

    * the outer ContentInfo wraps a SignedData holding id-ct-TSTInfo
      content and exactly one SignerInfo;
    * the SignerIdentifier issuer/serial matches the pinned certificate
      (certificates embedded in the token are never trusted);
    * the pinned certificate is valid at genTime, has a critical Extended
      Key Usage of exactly id-kp-timeStamping, allows digitalSignature
      when a Key Usage is present, and is not a CA certificate;
    * authenticatedAttributes are present and contain exactly one
      single-valued contentType attribute (id-ct-TSTInfo) and exactly one
      single-valued messageDigest attribute matching the encapsulated
      content;
    * the signature is RSA PKCS#1 v1.5 with SHA-256/384/512, anything
      else is rejected;
    * nonce, message imprint algorithm/length/value and policy (when
      given) match the request;
    * every DER layer is fully consumed, trailing data is rejected.

    Returns True on success, raises ValueError otherwise.
    '''
    if hashname not in STRICT_HASHNAMES:
        raise ValueError('unsupported hash algorithm for strict verification: %r' % (hashname,))
    hashobj = hashlib.new(hashname)
    if digest is None:
        if data is None:
            raise ValueError('check_timestamp_strict requires data or digest argument')
        if not isinstance(data, bytes):
            data = data.encode()
        hashobj.update(data)
        digest = hashobj.digest()
    elif len(digest) != hashobj.digest_size:
        raise ValueError(
            'digest length is wrong for %s: %d != %d' % (hashname, len(digest), hashobj.digest_size)
        )

    certificate = _load_pinned_certificate(certificate)

    if not isinstance(tst, rfc3161ng.TimeStampToken):
        tst = _decode_fully(tst, rfc3161ng.TimeStampToken(), 'TimeStampToken')

    # the token must be a SignedData wrapping a TSTInfo
    if tst['contentType'] != rfc2315.signedData:
        raise ValueError('token content type is not id-signedData: %s' % tst['contentType'])
    signed_data = tst['content']
    if not signed_data.isValue:
        raise ValueError('token carries no SignedData content')
    content_info = signed_data['contentInfo']
    if content_info['contentType'] != rfc3161ng.id_ct_TSTInfo:
        raise ValueError('encapsulated content type is not id-ct-TSTInfo: %s' % content_info['contentType'])
    if not content_info['content'].isValue:
        raise ValueError('SignedData carries no encapsulated content')
    econtent = _decode_fully(bytes(content_info['content']), univ.OctetString(), 'encapsulated content')
    tst_info = _decode_fully(bytes(econtent), rfc3161ng.TSTInfo(), 'TSTInfo')

    # exactly one signer, identified by the pinned certificate
    signer_infos = signed_data['signerInfos']
    if len(signer_infos) != 1:
        raise ValueError('expected exactly one SignerInfo, got %d' % len(signer_infos))
    signer_info = signer_infos[0]
    _check_signer_identity(signer_info, certificate)

    # the pinned certificate must be a TSA certificate valid at genTime
    gen_time = generalizedtime_to_utc_datetime(str(tst_info['genTime']), naive=False)
    _check_tsa_certificate(certificate, gen_time)

    # the signature must bind the authenticated attributes to the content
    signer_hashname = _get_signature_hash(signer_info, certificate)
    signed_attributes = _check_authenticated_attributes(signer_info, bytes(econtent), signer_hashname)
    try:
        certificate.public_key().verify(
            bytes(signer_info['encryptedDigest']),
            signed_attributes,
            padding.PKCS1v15(),
            getattr(hashes, signer_hashname.upper())(),
        )
    except InvalidSignature:
        raise ValueError('signature does not verify with the pinned TSA certificate')

    # bind the TSTInfo to the request
    if int(tst_info['version']) != 1:
        raise ValueError('unsupported TSTInfo version: %s' % tst_info['version'])
    if nonce is not None:
        if not tst_info['nonce'].isValue or int(tst_info['nonce']) != int(nonce):
            raise ValueError('nonce is different or missing')
    message_imprint = tst_info['messageImprint']
    if message_imprint['hashAlgorithm']['algorithm'] != get_hash_oid(hashname):
        raise ValueError('message imprint algorithm mismatch')
    imprint = bytes(message_imprint['hashedMessage'])
    if len(imprint) != hashobj.digest_size:
        raise ValueError('message imprint length mismatch')
    if imprint != digest:
        raise ValueError('message imprint mismatch')
    if policy is not None:
        if not tst_info['policy'].isValue or tst_info['policy'] != univ.ObjectIdentifier(str(policy)):
            raise ValueError('policy is different or missing')
    return True


class RemoteTimestamper(object):
    def __init__(self, url, certificate=None, capath=None, cafile=None, username=None, password=None, hashname=None, include_tsa_certificate=False, timeout=10, tsa_policy_id=None, strict=False):
        self.url = url
        self.certificate = certificate
        self.capath = capath
        self.cafile = cafile
        self.username = username
        self.password = password
        self.strict = strict
        # strict verification only accepts SHA-256/384/512
        self.hashname = hashname or ('sha256' if strict else 'sha1')
        self.include_tsa_certificate = include_tsa_certificate
        self.timeout = timeout
        self.tsa_policy_id = tsa_policy_id

    def check_response(self, response, digest, nonce=None):
        '''
           Check validity of a TimeStampResponse
        '''
        tst = response.time_stamp_token
        if self.strict:
            if not self.certificate:
                raise TimestampingError('strict mode requires a pinned TSA certificate')
            return self.check(tst, digest=digest, nonce=nonce)
        if self.certificate:
            return self.check(tst, digest=digest, nonce=nonce)
        return tst

    def check(self, tst, data=None, digest=None, nonce=None):
        if self.strict:
            return check_timestamp_strict(
                tst,
                digest=digest,
                data=data,
                nonce=nonce,
                certificate=self.certificate,
                hashname=self.hashname,
                policy=self.tsa_policy_id,
            )
        return check_timestamp(
            tst,
            digest=digest,
            data=data,
            nonce=nonce,
            certificate=self.certificate,
            hashname=self.hashname,
        )

    def timestamp(self, data=None, digest=None, include_tsa_certificate=None, nonce=None, tsa_policy_id=None):
        return self(
            data=data,
            digest=digest,
            include_tsa_certificate=include_tsa_certificate,
            nonce=nonce,
            tsa_policy_id=tsa_policy_id,
        )

    def __call__(self, data=None, digest=None, include_tsa_certificate=None, nonce=None, return_tsr=False, tsa_policy_id=None):
        if data:
            digest = data_to_digest(data, self.hashname)

        request = make_timestamp_request(
            data=data,
            digest=digest,
            hashname=self.hashname,
            include_tsa_certificate=include_tsa_certificate if include_tsa_certificate is not None else self.include_tsa_certificate,
            nonce=nonce,
            tsa_policy_id=tsa_policy_id if tsa_policy_id is not None else self.tsa_policy_id
        )
        binary_request = encode_timestamp_request(request)

        headers = {'Content-Type': 'application/timestamp-query'}
        if self.username is not None:
            username = self.username.encode() if not isinstance(self.username, bytes) else self.username
            password = self.password.encode() if not isinstance(self.password, bytes) else self.password
            base64string = base64.standard_b64encode(b'%s:%s' % (username, password))
            if isinstance(base64string, bytes):
                base64string = base64string.decode()
            headers['Authorization'] = "Basic %s" % base64string
        try:
            response = requests.post(
                self.url,
                data=binary_request,
                timeout=self.timeout,
                headers=headers,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise TimestampingError('Unable to send the request to %r' % self.url, exc)
        tsr = decode_timestamp_response(response.content)
        self.check_response(tsr, digest, nonce=nonce)
        if return_tsr:
            return tsr
        return encoder.encode(tsr.time_stamp_token)


def data_to_digest(data, hashname='sha1'):
    hashobj = hashlib.new(hashname)
    if not isinstance(data, bytes):
        data = data.encode()
    hashobj.update(data)
    return hashobj.digest()


def make_timestamp_request(data=None, digest=None, hashname='sha1', include_tsa_certificate=False, nonce=None, tsa_policy_id=None):
    algorithm_identifier = rfc2459.AlgorithmIdentifier()
    algorithm_identifier.setComponentByPosition(0, get_hash_oid(hashname))
    message_imprint = rfc3161ng.MessageImprint()
    message_imprint.setComponentByPosition(0, algorithm_identifier)
    hashobj = hashlib.new(hashname)
    if digest:
        assert len(digest) == hashobj.digest_size, 'digest length is wrong %s != %s' % (len(digest), hashobj.digest_size)
    elif data:
        digest = data_to_digest(data)
    else:
        raise ValueError('You must pass some data to digest, or the digest')
    message_imprint.setComponentByPosition(1, digest)
    tsq = rfc3161ng.TimeStampReq()
    tsq.setComponentByPosition(0, 'v1')
    tsq.setComponentByPosition(1, message_imprint)
    if tsa_policy_id:
        tsq.setComponentByPosition(2, rfc3161ng.types.TSAPolicyId(tsa_policy_id))
    if nonce is not None:
        tsq.setComponentByPosition(3, int(nonce))
    tsq.setComponentByPosition(4, include_tsa_certificate)
    return tsq


def encode_timestamp_request(request):
    return encoder.encode(request)


def encode_timestamp_response(response):
    return encoder.encode(response)


def decode_timestamp_request(request):
    tsq, substrate = decoder.decode(request, asn1Spec=rfc3161ng.TimeStampReq())
    if substrate:
        raise ValueError('Extra data returned')
    return tsq


def decode_timestamp_response(response):
    tsr, substrate = decoder.decode(response, asn1Spec=rfc3161ng.TimeStampResp())
    if substrate:
        raise ValueError('Extra data returned')
    return tsr
