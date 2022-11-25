import binascii
import codecs
import re
import struct
import typing

FLIPPER_NFC_HEADER = '''\
Filetype: Flipper NFC device
Version: 2
# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card
Device type: Mifare Classic
# UID, ATQA and SAK are common for all formats
UID: {uid}
ATQA: {atqa}
SAK: {sak}
# Mifare Classic specific data
Mifare Classic type: {type}
Data format version: 2
# Mifare Classic blocks, '??' means unknown data'''


def format_hexdata(data: str) -> str:
    return " ".join(data[i:i + 2] for i in range(0, len(data), 2)).upper()


def extract_value(data: str) -> int:
    """Extracts numeric value from Mifare value field"""
    data = re.sub(r'\s', '', data)
    length = 8
    numbers = []
    for i in range(0, length*3, length):
        binary = binascii.unhexlify(data[i:i+length])
        numbers.append(struct.unpack('i', binary)[0])

    a, b, c = numbers[0], ~numbers[1], numbers[2]
    if not (a == b == c):
        raise ValueError('Invalid value field')

    return a


class Extractor:
    KEY_LENGTH = 12
    UID_LENGTH = 8

    def __init__(self, filehandle):
        self.filehandle = filehandle

        data = self.filehandle.read()
        self.data_size = len(data)
        self.data = self.read(data)

    def extract_keys(self) -> typing.Set[str]:
        keys = set()

        for sector in self.data:
            block = sector[-1]
            key_a = block[0:self.KEY_LENGTH]
            key_b = block[-self.KEY_LENGTH:]

            keys.add(key_a)
            keys.add(key_b)

        return keys

    def flipper_blocks(self):
        data = [
            FLIPPER_NFC_HEADER.format(
                uid=format_hexdata(self.data[0][0][:self.UID_LENGTH]),
                atqa=format_hexdata(self.data[0][0][12:12+4]),
                sak=format_hexdata(self.data[0][0][10:10+2]),
                type='4K' if self.data_size == 4096 else '1K'
            )
        ]

        # dump blocks
        block_id = 0
        for sector in self.data:
            for block in sector:
                data.append(f"Block {block_id}: {format_hexdata(block)}")
                block_id += 1

        return "\n".join(data)

    def read(self, data):
        blocksmatrix = []
        data_size = len(data)

        if data_size not in {4096, 1024, 320}:
            raise ValueError("Wrong file size: %d bytes.\nOnly 320, 1024 or 4096 bytes allowed." % data_size)

        # read all sectors
        sector_number = 0
        start = 0
        end = 64
        while True:
            sector = data[start:end]
            sector = codecs.encode(sector, 'hex')
            if not isinstance(sector, str):
                sector = str(sector, 'ascii')
            sectors = [sector[x:x + 32] for x in range(0, len(sector), 32)]

            blocksmatrix.append(sectors)

            # after 32 sectors each sector has 16 blocks instead of 4
            sector_number += 1
            if sector_number < 32:
                start += 64
                end += 64
            elif sector_number == 32:
                start += 64
                end += 256
            else:
                start += 256
                end += 256

            if start == data_size:
                break

        return blocksmatrix


class Flipper:
    def __init__(self, filehandle):
        self.data = filehandle.read()

    def mfd_data(self) -> typing.Tuple[typing.Dict[int, bytes], bool]:
        missing_data = False
        matches = re.finditer(r'Block (?P<id>\d+): (?P<data>([0-9a-f?]{2} ?)+)', self.data, re.IGNORECASE)
        blocks = {}
        for m in matches:
            blocks[int(m.group('id'))] = m.group('data')

        if not blocks:
            raise ValueError('Missing data')

        # decode blocks
        decoded = {}
        for key, block in blocks.items():
            repl = re.sub(r'\?{2}', '00', block)
            if repl != block:
                missing_data = True

            repl = repl.replace(' ', '').lower()
            decoded[key] = b''.join(struct.pack('H', int(repl[i:i+4], base=16)) for i in range(0, len(repl), 4))

        return decoded, missing_data
