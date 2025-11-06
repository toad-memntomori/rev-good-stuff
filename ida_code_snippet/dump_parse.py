import ida_bytes
import ida_segment
import struct

class ParameterError(Exception): pass

def dump_bytes(address : int, size : int) -> bytes:
    if address < 0:
        raise ParameterError(f"address : {address:#x}")
    if size <= 0:
        raise ParameterError(f"size : {size:#x}")

    seg = ida_segment.getseg(address)
    if seg is None:
        raise RuntimeError(f"Address {address:#x} is not in any segment")
    
    end_addr = address + size
    if end_addr > seg.end_ea:
        raise RuntimeError(
            f"Failed to dump bytes: requested range [{address:#x}, {end_addr:#x}) "
            f"exceeds segment boundary (segment ends at {seg.end_ea:#x})"
        )

    result = ida_bytes.get_bytes(address, size)

    if result is None:
        raise RuntimeError(f"Failed to read {size} bytes at address {address:#x}")
    
    return result

def convert_string(data : bytes, encode : str) -> str:
    try:
        result = data.decode(encoding=encode)
        return result
    except LookupError as e:
        raise ParameterError(f"Invalid encoding: {encode} : {e}") from e
    except UnicodeDecodeError as e:
        raise RuntimeError(f"Failed to decode data with encoding {encode} : {e}") from e

def convert_hex(data : bytes) -> str:
    return data.hex()

def convert_unsigned_long(data : bytes, isLittleEndian : bool) -> int:
    if len(data) != 8:
        raise ParameterError(f"Failed to convert to long: data size must be 8 bytes, got {len(data)} bytes")
    
    parsefmt = "<Q" if isLittleEndian else ">Q"
    
    return struct.unpack(parsefmt, data)[0]

def convert_long(data : bytes, isLittleEndian : bool) -> int:
    if len(data) != 8:
        raise ParameterError(f"Failed to convert to long: data size must be 8 bytes, got {len(data)} bytes")
    
    parsefmt = "<q" if isLittleEndian else ">q"
    
    return struct.unpack(parsefmt, data)[0]

def convert_unsigned_integer(data : bytes, isLittleEndian : bool) -> int:
    if len(data) != 4:
        raise ParameterError(f"Failed to convert to integer: data size must be 4 bytes, got {len(data)} bytes")
    
    parsefmt = "<I" if isLittleEndian else ">I"
    
    return struct.unpack(parsefmt, data)[0]

def convert_integer(data : bytes, isLittleEndian : bool) -> int:
    if len(data) != 4:
        raise ParameterError(f"Failed to convert to integer: data size must be 4 bytes, got {len(data)} bytes")
    
    parsefmt = "<i" if isLittleEndian else ">i"
    
    return struct.unpack(parsefmt, data)[0]

def convert_unsigned_short(data : bytes, isLittleEndian : bool) -> int:
    if len(data) != 2:
        raise ParameterError(f"Failed to convert to short: data size must be 2 bytes, got {len(data)} bytes")
    
    parsefmt = "<H" if isLittleEndian else ">H"
    
    return struct.unpack(parsefmt, data)[0]

def convert_short(data : bytes, isLittleEndian : bool) -> int:
    if len(data) != 2:
        raise ParameterError(f"Failed to convert to short: data size must be 2 bytes, got {len(data)} bytes")
    
    parsefmt = "<h" if isLittleEndian else ">h"
    
    return struct.unpack(parsefmt, data)[0]

def convert_unsigned_byte(data : bytes) -> int:
    if len(data) != 1:
        raise ParameterError(f"Failed to convert to byte: data size must be 1 byte, got {len(data)} bytes")
    
    return data[0]

def convert_float(data : bytes, isLittleEndian : bool) -> float:
    if len(data) != 4:
        raise ParameterError(f"Failed to convert to float: data size must be 4 bytes, got {len(data)} bytes")
    
    parsefmt = "<f" if isLittleEndian else ">f"
    
    return struct.unpack(parsefmt, data)[0]

def convert_double(data : bytes, isLittleEndian : bool) -> float:
    if len(data) != 8:
        raise ParameterError(f"Failed to convert to double: data size must be 8 bytes, got {len(data)} bytes")
    
    parsefmt = "<d" if isLittleEndian else ">d"
    
    return struct.unpack(parsefmt, data)[0]

