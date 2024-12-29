from binascii import hexlify, unhexlify


def toHex(value):
    return hexlify(value).decode('utf-8')
def fromHex(value):
    return unhexlify(value)