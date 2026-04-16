import struct
import json

def pack(data):
    json_data = json.dumps(data)
    json_bytes = json_data.encode('utf-8')
    length = len(json_bytes)
    return struct.pack('!I', length) + json_bytes

def unpack(data):
    if len(data) < 4:
        return None, data
    length = struct.unpack('!I', data[:4])[0]
    if len(data) < 4 + length:
        return None, data
    json_data = data[4:4+length]
    remaining = data[4+length:]
    try:
        unpacked_data = json.loads(json_data.decode('utf-8'))
        return unpacked_data, remaining
    except:
        return None, data