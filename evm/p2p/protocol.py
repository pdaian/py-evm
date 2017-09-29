import logging
import struct

import rlp
from rlp import sedes

from evm.constants import NULL_BYTE


class Command:
    _id = None
    decode_strict = True
    structure = []

    def __init__(self, id_offset):
        self.id_offset = id_offset

    @property
    def id(self):
        return self.id_offset + self._id

    def encode_payload(self, data):
        if isinstance(data, dict):  # convert dict to ordered list
            if not isinstance(self.structure, list):
                raise ValueError("Command.structure must be a list when data is a dict")
            expected_keys = sorted(name for name, _ in self.structure)
            data_keys = sorted(data.keys())
            if data_keys != expected_keys:
                raise rlp.EncodingError(
                    "Keys in data dict ({}) do not match expected keys ({})".format(
                        data_keys, expected_keys))
            data = [data[name] for name, _ in self.structure]
        if isinstance(self.structure, sedes.CountableList):
            encoder = self.structure
        else:
            encoder = sedes.List([type_ for _, type_ in self.structure])
        return rlp.encode(data, sedes=encoder)

    def decode_payload(self, rlp_data):
        if isinstance(self.structure, sedes.CountableList):
            decoder = self.structure
        else:
            decoder = sedes.List(
                [type_ for _, type_ in self.structure], strict=self.decode_strict)
        data = rlp.decode(rlp_data, sedes=decoder)
        if isinstance(self.structure, sedes.CountableList):
            return data
        else:
            return {
                field_name: value
                for ((field_name, _), value)
                in zip(self.structure, data)
            }

    def decode(self, data):
        packet_type = rlp.decode(data[:1], sedes=sedes.big_endian_int)
        if packet_type != self.id:
            raise ValueError("Wrong packet type: {}".format(packet_type))
        return self.decode_payload(data[1:])

    def encode(self, data):
        payload = self.encode_payload(data)
        enc_cmd_id = rlp.encode(self.id, sedes=rlp.sedes.big_endian_int)
        frame_size = len(enc_cmd_id) + len(payload)
        if frame_size.bit_length() > 24:
            raise ValueError("Frame size has to fit in a 3-byte integer")

        # Drop the first byte as, per the spec, frame_size must be a 3-byte int.
        header = struct.pack('>I', frame_size)[1:]
        header = _pad_to_16_byte_boundary(header)

        body = _pad_to_16_byte_boundary(enc_cmd_id + payload)
        return header, body


class Protocol:
    logger = logging.getLogger("evm.p2p.protocol.Protocol")
    name = None
    version = None
    # List of Command classes that this protocol supports.
    _commands = []

    def __init__(self, peer, cmd_id_offset):
        self.peer = peer
        self.cmd_id_offset = cmd_id_offset
        self.commands = [cmd_class(cmd_id_offset) for cmd_class in self._commands]
        self.cmd_by_id = dict((cmd.id, cmd) for cmd in self.commands)

    def process(self, cmd_id, msg):
        cmd = self.cmd_by_id[cmd_id]
        return cmd.handle(self, msg)

    def send(self, header, body):
        self.peer.send(header, body)


def _pad_to_16_byte_boundary(data):
    """Pad the given data with NULL_BYTE up to the next 16-byte boundary."""
    remainder = len(data) % 16
    if remainder != 0:
        data += NULL_BYTE * (16 - remainder)
    return data
