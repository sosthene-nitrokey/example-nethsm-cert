import cryptography
import nethsm
import datetime
from nethsm import Base64, SignMode
from typing import Optional, Sequence, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import Encoding


admin_passphrase = "adminadmin"
unlock_passphrase = "unlockunlock"
operator_username = "operator"
operator_passphrase = "opPassphrase"

class RsaNethsmSigner(rsa.RSAPrivateKey):
    _client: nethsm.NetHSM
    _key_reference: str
    _public_key: rsa.RSAPublicKey

    def __init__(
        self, client: nethsm.NetHSM, key_reference: str, public_key: rsa.RSAPublicKey
    ):
        self._client = client
        self._key_reference = key_reference
        self._public_key = public_key

    def public_key(self) -> rsa.RSAPublicKey:
        return self._public_key

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        assert not isinstance(algorithm, asym_utils.Prehashed)
        assert isinstance(padding, PKCS1v15)
        assert isinstance(algorithm, hashes.SHA256)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        data = digest.finalize()

        return self._client.sign(key_id = self._key_reference, data =  Base64.encode(data), mode = SignMode.PKCS1).decode()

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()

with nethsm.connect(
    host="nethsmdemo.nitrokey.com",
    auth=nethsm.Authentication(username="admin", password=admin_passphrase),
) as client:
    assert client.get_state() == nethsm.State.OPERATIONAL
    key = client.generate_key(
        type=nethsm.KeyType.RSA,
        length=2048,
        mechanisms=[
            nethsm.KeyMechanism.RSA_SIGNATURE_PKCS1,
            nethsm.KeyMechanism.RSA_DECRYPTION_PKCS1,
            nethsm.KeyMechanism.RSA_SIGNATURE_PSS_SHA256,
            nethsm.KeyMechanism.RSA_DECRYPTION_OAEP_SHA256, 
        ],
    )

with nethsm.connect(
    host="nethsmdemo.nitrokey.com",
    auth=nethsm.Authentication(username=operator_username, password=operator_passphrase),
) as client:
    public_key_pem = client.get_key_public_key(key)
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    signer = RsaNethsmSigner(client, key, public_key)

    certificate_builder = x509.CertificateBuilder()
    domain_component = ["nethsmdemo","nitrokey","com"]
    subject_name = ["demo", "certificate"]
    crypto_rdns = x509.Name(
        [
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, subject)
                    for subject in domain_component
                ]
            ),
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)
                    for subject in subject_name
                ]
            ),
        ]
    )

    certificate_builder = (
        certificate_builder.subject_name(crypto_rdns)
        .issuer_name(crypto_rdns)
        .not_valid_before(datetime.datetime(2000, 1, 1, 0, 0))
        .not_valid_after(datetime.datetime(2099, 1, 1, 0, 0))
        .serial_number(x509.random_serial_number())
        .public_key(public_key)
    )
    crypto_extensions: Sequence[Tuple[x509.ExtensionType, bool]] = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        ),
    ]

    for ext, critical in crypto_extensions:
        certificate_builder = certificate_builder.add_extension(ext, critical)


    certificate = certificate_builder.sign(signer, hashes.SHA256())


with nethsm.connect(
    host="nethsmdemo.nitrokey.com",
    auth=nethsm.Authentication(username="admin", password=admin_passphrase),
) as client:
    client.set_key_certificate(key, certificate.public_bytes(Encoding.PEM))
