=========
rfc3161ng
=========

.. image:: https://img.shields.io/pypi/l/rfc3161ng.svg
   :target: https://raw.githubusercontent.com/trbs/rfc3161ng/master/LICENSE

.. image:: https://github.com/trbs/rfc3161ng/workflows/CI/badge.svg?branch=master
     :target: https://github.com/trbs/rfc3161ng/actions?workflow=CI
     :alt: CI Status

.. image:: https://img.shields.io/pypi/v/rfc3161ng.svg
    :target: https://pypi.python.org/pypi/rfc3161ng/
    :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/wheel/rfc3161ng.svg
    :target: https://pypi.python.org/pypi/rfc3161ng/
    :alt: Supports Wheel format

A simple client library for cryptographic timestamping service implementing the
protocol from RFC3161.

This started as a fork of https://dev.entrouvert.org/projects/python-rfc3161 and
has some additional patches such as Python3 support.

The latest version of this library is available from
https://github.com/trbs/rfc3161ng/ .


Public providers
================

There are several timestamping services around.  Here is a list of
publicly available services you can try:

 * http://freetsa.org/tsr
 * http://time.certum.pl
 * http://timestamp.comodoca.com/rfc3161
 * http://timestamp.geotrust.com/tsa
 * http://timestamp.globalsign.com/scripts/timstamp.dll
 * http://tsa.starfieldtech.com
 * https://teszt.e-szigno.hu:440/tsa

Example
=======

    >>> import rfc3161ng
    >>> certificate = open('data/certum_certificate.crt', 'rb').read()
    >>> rt = rfc3161ng.RemoteTimestamper('http://time.certum.pl', certificate=certificate)
    >>> tst = rt.timestamp(data=b'John Doe')
    >>> rt.check(tst, data=b'John Doe')
    True
    >>> rfc3161ng.get_timestamp(tst)
    datetime.datetime(2017, 8, 31, 15, 42, 58, tzinfo=tzutc())

Example for a server that insist on SHA256:

    >>> import rfc3161ng
    >>> timestamper = rfc3161ng.RemoteTimestamper('https://interop.redwax.eu/test/timestamp', hashname='sha256')
    >>> tsr = timestamper(data=b'The RedWax Project', return_tsr=True)
    >>> print('{}'.format(tsr))

Verifying timestamp using OpenSSL
=================================

One can verify the timestamp returned by the timeserver by using OpenSSL.
For example with:

  $ openssl ts -verify -data data_file.txt -in data_file.tsr -CAfile cacert.pem -untrusted tsa.crt

To save the tsr you can use code similar to:

    >>> from pyasn1.codec.der import encoder
    >>> import rfc3161ng
    >>> ...
    >>> timestamper = rfc3161ng.RemoteTimestamper('http://freetsa.org/tsr', certificate=certificate_data)
    >>> tsr = timestamper(data=data_file.read(), return_tsr=True)
    >>> with open("data_file.tsr", "wb") as f:
    >>>     f.write(encoder.encode(tsr))

Alternatively you can just save the raw `response.content` returned from the certification server.

There is a test which also covers this in `test_verify_timestamp_response_with_openssl`.

Strict verification
===================

The default ``check_timestamp`` only checks that *some* signature verifies.
Strict verification additionally binds the token to a TSA certificate pinned
by the caller: the signer must be identified by that certificate's
issuer/serial, the certificate must be valid at ``genTime`` and carry a
critical Extended Key Usage of exactly ``id-kp-timeStamping`` (CA
certificates are rejected), the token must hold exactly one ``SignerInfo``
with well-formed signed attributes (single-valued ``contentType`` and
``messageDigest`` matching the TSTInfo), only RSA PKCS#1 v1.5 with
SHA-256/384/512 is accepted, and the nonce, message imprint and policy must
match the request. Certificates embedded in the token are never trusted.

    >>> import rfc3161ng
    >>> certificate = open('data/certum_certificate.crt', 'rb').read()
    >>> rfc3161ng.check_timestamp_strict(tst, certificate, data=b'John Doe',
    ...                                  hashname='sha256', nonce=nonce)
    True

The same rules can be enabled on ``RemoteTimestamper`` with ``strict=True``
(verification then also applies to the ``return_tsr=True`` path):

    >>> rt = rfc3161ng.RemoteTimestamper('http://time.certum.pl', certificate=certificate,
    ...                                  hashname='sha256', strict=True)
    >>> tst = rt.timestamp(data=b'John Doe', nonce=nonce)


Authors
=======

 * Benjamin Dauvergne <bdauvergne@entrouvert.com>
 * Michael Gebetsroither <michael@mgeb.org>
 * Bas van Oostveen <trbs@trbs.net>
