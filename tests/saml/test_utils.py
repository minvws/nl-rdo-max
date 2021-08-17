import base64, zlib

def decode_base64_and_inflate( b64string ):
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data , -15)
