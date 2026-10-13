"""Veil Local Certificate Authority & Dynamic Leaf Certificate Minting.

Generates and manages device-unique Root CA and dynamically mints leaf
certificates for transparent AI endpoint SSL termination.
"""
from __future__ import annotations

import datetime
import logging
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger("veil.proxy.ca")

CA_COMMON_NAME = "Veil Local Security CA"
CA_ORGANIZATION = "Veil Privacy Shield"


class CertificateAuthority:
    """Device-unique Root CA and dynamic leaf certificate issuer."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = (base_dir or (Path.home() / ".veil" / "ca")).resolve()
        self.ca_key_path = self.base_dir / "ca.key"
        self.ca_cert_path = self.base_dir / "ca.crt"
        self.certs_dir = self.base_dir / "certs"
        self._root_key: Optional[rsa.RSAPrivateKey] = None
        self._root_cert: Optional[x509.Certificate] = None
        self._ssl_contexts: Dict[str, ssl.SSLContext] = {}

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create_root_ca(self) -> Tuple[Path, Path]:
        """Loads existing Root CA or generates a device-unique one."""
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            try:
                key_bytes = self.ca_key_path.read_bytes()
                cert_bytes = self.ca_cert_path.read_bytes()
                self._root_key = serialization.load_pem_private_key(
                    key_bytes, password=None
                )
                self._root_cert = x509.load_pem_x509_certificate(cert_bytes)
                logger.info("Loaded existing Veil Root CA from %s", self.ca_cert_path)
                return self.ca_key_path, self.ca_cert_path
            except Exception as e:
                logger.warning("Failed to load existing CA (%s). Regenerating fresh CA...", e)

        # Generate fresh device-unique Root CA
        logger.info("Generating fresh device-unique Veil Root CA...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        self.ca_key_path.write_bytes(key_pem)
        self.ca_cert_path.write_bytes(cert_pem)

        # Restrict permissions on Windows/POSIX
        try:
            os.chmod(self.ca_key_path, 0o600)
        except Exception:
            pass

        self._root_key = private_key
        self._root_cert = cert
        logger.info("Generated Veil Root CA saved at %s", self.ca_cert_path)
        return self.ca_key_path, self.ca_cert_path

    def get_or_create_leaf_cert(self, hostname: str) -> Tuple[Path, Path]:
        """Dynamically generates and signs a leaf cert for target domain."""
        if self._root_key is None or self._root_cert is None:
            self.load_or_create_root_ca()

        # Sanitize hostname for filesystem storage
        safe_name = "".join(c if c.isalnum() or c in ".-" else "_" for c in hostname)
        cert_path = self.certs_dir / f"{safe_name}.crt"
        key_path = self.certs_dir / f"{safe_name}.key"

        if cert_path.exists() and key_path.exists():
            return key_path, cert_path

        leaf_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        san_dns = [x509.DNSName(hostname)]
        if not hostname.startswith("*."):
            san_dns.append(x509.DNSName(f"*.{hostname}"))

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))  # 1 year
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_dns),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .sign(self._root_key, hashes.SHA256())
        )

        key_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        key_path.write_bytes(key_pem)
        cert_path.write_bytes(cert_pem)
        return key_path, cert_path

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """Returns a cached server SSLContext configured for the given hostname."""
        if hostname in self._ssl_contexts:
            return self._ssl_contexts[hostname]

        key_path, cert_path = self.get_or_create_leaf_cert(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._ssl_contexts[hostname] = ctx
        return ctx

    # -------------------------------------------------------------------------
    # Windows User Trust Store Integration
    # -------------------------------------------------------------------------

    def is_root_ca_installed(self) -> bool:
        """Checks if Veil Root CA is trusted in the current user root store."""
        if sys.platform != "win32":
            return False

        try:
            cmd = ["certutil", "-store", "-user", "Root", CA_COMMON_NAME]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return res.returncode == 0 and CA_COMMON_NAME in res.stdout
        except Exception as e:
            logger.error("Failed to query Windows cert store: %s", e)
            return False

    def install_root_ca(self) -> Tuple[bool, str]:
        """Installs Veil Root CA into CurrentUser Root store via certutil."""
        if sys.platform != "win32":
            return False, "Non-Windows OS: root CA store installation not supported."

        self.load_or_create_root_ca()
        if not self.ca_cert_path.exists():
            return False, f"Root CA certificate file missing at {self.ca_cert_path}"

        if self.is_root_ca_installed():
            return True, "Veil Root CA is already installed and trusted."

        try:
            cmd = ["certutil", "-addstore", "-user", "Root", str(self.ca_cert_path)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                logger.info("Successfully added Veil Root CA to CurrentUser store.")
                return True, "Veil Root CA successfully installed into CurrentUser Root store."
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                logger.warning("certutil -addstore returned error: %s", err_msg)
                return False, f"certutil failed: {err_msg}"
        except subprocess.TimeoutExpired:
            return False, "Windows prompt timed out. Please click 'Yes' on the Windows Security Warning dialog to trust Veil Root CA."
        except Exception as e:
            logger.exception("Exception during certutil -addstore: %s", e)
            return False, str(e)

    def uninstall_root_ca(self) -> Tuple[bool, str]:
        """Removes Veil Root CA from CurrentUser Root store via certutil."""
        if sys.platform != "win32":
            return False, "Non-Windows OS: root CA store removal not supported."

        try:
            cmd = ["certutil", "-delstore", "-user", "Root", CA_COMMON_NAME]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0 or "not found" in res.stdout.lower():
                logger.info("Successfully removed Veil Root CA from CurrentUser store.")
                return True, "Veil Root CA removed from CurrentUser Root store."
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                return False, f"certutil removal error: {err_msg}"
        except Exception as e:
            logger.exception("Exception during certutil -delstore: %s", e)
            return False, str(e)


# Default singleton
ca_instance = CertificateAuthority()
