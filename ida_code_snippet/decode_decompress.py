import base64
import zlib
import bz2
import lzma

class DecodeError(Exception): pass
class DecompressError(Exception): pass

def decode_base85(encoded_string : str) -> bytes:
    try:
        return base64.b85decode(encoded_string)
    except Exception as e:
        raise DecodeError(f"Failed to decode data with base85 encoding: {e}") from e

def decode_base64(encoded_string : str) -> bytes:
    try:
        return base64.b64decode(encoded_string)
    except Exception as e:
        raise DecodeError(f"Failed to decode data with base64 encoding: {e}") from e

def decode_base16(encoded_string : str) -> bytes:
    try:
        return bytes.fromhex(encoded_string)
    except Exception as e:
        raise DecodeError(f"Failed to decode data with base16 encoding: {e}") from e

def decompress_zlib(compressed_data : bytes) -> bytes:
    try:
        return zlib.decompress(compressed_data)
    except Exception as e:
        raise DecompressError(f"Failed to decompress data with zlib: {e}") from e

def decompress_bzip2(compressed_data : bytes) -> bytes:
    try:
        return bz2.decompress(compressed_data)
    except Exception as e:
        raise DecompressError(f"Failed to decompress data with bzip2: {e}") from e

def decompress_lzma(compressed_data : bytes) -> bytes:
    try:
        return lzma.decompress(compressed_data)
    except Exception as e:
        raise DecompressError(f"Failed to decompress data with lzma: {e}") from e

