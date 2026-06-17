import os
import hashlib
import re
from app.utils import get_logger

logger = get_logger(__name__)

class FileCarver:
    """
    Ultra-Expert File Carver.
    Extracts files from raw HTTP payloads.
    """
    def __init__(self, output_dir="extracted_files"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def carve_http_payload(self, payload_raw, source_ip):
        """
        Attempts to extract files from raw hex payloads.
        Supports common magic numbers: PNG, JPG, PDF, EXE.
        """
        if not payload_raw:
            return None

        # Magic Numbers (Hex)
        signatures = {
            "png": "89504e470d0a1a0a",
            "jpg": "ffd8ffe0",
            "pdf": "25504446",
            "exe": "4d5a"
        }

        for file_type, magic in signatures.items():
            if magic in payload_raw:
                start_idx = payload_raw.find(magic)
                # In a real carver, we'd need to find the EOF or use Content-Length
                # For this expert demo, we extract a chunk
                file_data_hex = payload_raw[start_idx:start_idx + 100000] # Max 50KB chunk
                
                try:
                    file_data = bytes.fromhex(file_data_hex)
                    file_hash = hashlib.md5(file_data).hexdigest()
                    filename = f"{source_ip}_{file_hash}.{file_type}"
                    filepath = os.path.join(self.output_dir, filename)
                    
                    with open(filepath, "wb") as f:
                        f.write(file_data)
                    
                    logger.info(f"File Carved: {filename} ({file_type}) from {source_ip}")
                    return filepath
                except Exception as e:
                    logger.error(f"Carving Error: {e}")
        
        return None
