import hashlib

try:
    from scapy.layers.tls.all import TLSClientHello
except ImportError:
    TLSClientHello = None


def generate_ja3(packet):
    """Generate a JA3-like fingerprint from a TLS ClientHello packet when available."""
    if TLSClientHello is None or not packet.haslayer(TLSClientHello):
        return None

    tls_layer = packet.getlayer(TLSClientHello)

    version = str(getattr(tls_layer, "version", ""))
    ciphers = "-".join(str(cipher) for cipher in getattr(tls_layer, "ciphers", []))

    extensions = ""
    curves = ""
    point_formats = ""

    for extension in getattr(tls_layer, "extensions", []) or []:
        extension_type = getattr(extension, "type", None)
        if extension_type is not None:
            extensions += f"{extension_type}-"

        if extension_type == 10 and hasattr(extension, "groups"):
            curves = "-".join(str(group) for group in extension.groups)

        if extension_type == 11 and hasattr(extension, "ec_point_formats"):
            point_formats = "-".join(str(point) for point in extension.ec_point_formats)

    extensions = extensions.rstrip("-")
    ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    return {
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash,
    }
