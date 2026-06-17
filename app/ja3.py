import hashlib
from scapy.all import TLS, TLSClientHello, Raw

def generate_ja3(packet):
    """
    Generates a JA3 fingerprint from a TLS Client Hello packet.
    JA3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    """
    if not packet.haslayer(TLSClientHello):
        return None

    tls_layer = packet.getlayer(TLSClientHello)
    
    # 1. SSL Version
    version = str(tls_layer.version)
    
    # 2. Ciphers
    ciphers = "-".join([str(c) for c in tls_layer.ciphers])
    
    # 3. Extensions
    extensions = ""
    if hasattr(tls_layer, 'extensions'):
        extensions = "-".join([str(e.type) for e in tls_layer.extensions])
        
    # 4. Elliptic Curves
    curves = ""
    # 5. Elliptic Curve Point Formats
    point_formats = ""
    
    if hasattr(tls_layer, 'extensions'):
        for ext in tls_layer.extensions:
            if ext.type == 10: # supported_groups (curves)
                if hasattr(ext, 'groups'):
                    curves = "-".join([str(g) for g in ext.groups])
            if ext.type == 11: # ec_point_formats
                if hasattr(ext, 'ec_point_formats'):
                    point_formats = "-".join([str(f) for f in ext.ec_point_formats])

    ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    
    return {
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash
    }
