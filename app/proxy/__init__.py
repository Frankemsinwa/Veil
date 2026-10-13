"""Veil Transparent Proxy Package.

Provides local Root CA management, Windows WinINet system proxy toggles,
and dynamic transparent SSL interception for AI providers.
"""
from app.proxy.ca import CertificateAuthority, ca_instance
from app.proxy.wininet import WindowsProxyManager, proxy_manager
from app.proxy.interceptor import TransparentProxyServer, transparent_proxy_server, DomainClassifier

__all__ = [
    "CertificateAuthority",
    "ca_instance",
    "WindowsProxyManager",
    "proxy_manager",
    "TransparentProxyServer",
    "transparent_proxy_server",
    "DomainClassifier",
]
