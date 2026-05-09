import ctypes
from bcc import libbcc
import sys

def get_map_fd(map_path):
    map_fd = bpf_obj_get(map_path)
    if map_fd < 0:
        print(f"Failed to open BPF map: {map_path}")
        sys.exit(1)
    return map_fd


def bpf_obj_get(path):
    return libbcc.lib.bpf_obj_get(bytes(path, "utf-8"))


class MyCTypes:
    prog_id = ctypes.c_uint16
    socket_cookie = ctypes.c_uint64
    pid = ctypes.c_uint32
    port = ctypes.c_uint16
    protocol = ctypes.c_uint16
    smallest_num = ctypes.c_uint8

class ProgramName(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 255),
    ]

    def __init__(self, value):
        # print(value)
        #if len(value) < 255:
        #    value += [0] * (255 - len(value))
        super().__init__(value)

    @property
    def value(self):
        return (self.name)

class ProgIdPort(ctypes.Structure):
    _fields_ = [
        ("prog_id", MyCTypes.prog_id),
        ("port", MyCTypes.port)
    ]

    def __init__(self, value = [0, 0]):
        # print(value)
        super().__init__(value[0], value[1])

    @property
    def value(self):
        return (self.prog_id, self.port)

    @value.setter
    def value(self, new_value):
        self.prog_id = new_value[0]
        self.port = new_value[1]

class ProgIdProtocol(ctypes.Structure):
    _fields_ = [
        ("prog_id", MyCTypes.prog_id),
        ("protocol", MyCTypes.protocol)
    ]

    def __init__(self, value = [0, 0]):
        # print(value)
        super().__init__(value[0], value[1])

    @property
    def value(self):
        return (self.prog_id, self.protocol)

    @value.setter
    def value(self, new_value):
        self.prog_id = new_value[0]
        self.protocol = new_value[1]


MyCTypes.prog_id_port = ProgIdPort
MyCTypes.prog_id_protocol = ProgIdProtocol
MyCTypes.program_name = ProgramName

class BPFMap:
    def __init__(self, map_path):
        self.map_path = map_path
        self.map_fd = get_map_fd(map_path)

    key_ctype = None

    value_ctype = None


    def add_entry(self, key, value):
        converted_key = self.key_ctype(key)
        converted_value = self.value_ctype(value)
        res = libbcc.lib.bpf_update_elem(self.map_fd, ctypes.byref(converted_key), ctypes.byref(converted_value), 0)
        if res != 0:
            print(f"Failed to add entry: {key} -> {value}, err: {res}")
            return
        print(f"Added: {key} -> {value}")

    def delete_entry(self, key):
        converted_key = self.key_ctype(key)
        res = libbcc.lib.bpf_delete_elem(self.map_fd, ctypes.byref(converted_key))
        if res != 0:
            print(f"Failed to delete entry: {key}, err: {res}")
            return
        print(f"Deleted: {key}")

    def show_map(self):
        print("Showing map entries...")
        
        key = self.key_ctype()
        next_key = self.key_ctype()
        
        value = self.value_ctype()

        res = libbcc.lib.bpf_get_next_key(self.map_fd, None, ctypes.byref(next_key))

        if res != 0:
            print("Map is empty or failed to get first key.")
            return

        while res == 0:
            lookup_res = libbcc.lib.bpf_lookup_elem(self.map_fd, ctypes.byref(next_key), ctypes.byref(value))
            
            if lookup_res == 0:
                port = next_key.value
                
                print(f"entry: {port} -> {value.value}")
            else:
                print(f"Failed to lookup value for raw key: {next_key.value}")

            key.value = next_key.value
            res = libbcc.lib.bpf_get_next_key(self.map_fd, ctypes.byref(key), ctypes.byref(next_key))

class PortsMap(BPFMap):
    key_ctype = MyCTypes.port
    value_ctype = MyCTypes.smallest_num

class CookiesPidMap(BPFMap):
    key_ctype = MyCTypes.socket_cookie

    value_ctype = MyCTypes.prog_id

class PidProgIdMap(BPFMap):
    key_ctype = MyCTypes.pid

    value_ctype = MyCTypes.prog_id



class ProgIdPortsMap(BPFMap):
    key_ctype = MyCTypes.prog_id_port
    value_ctype = MyCTypes.smallest_num

class ProgIdProtocolsMap(BPFMap):
    key_ctype = MyCTypes.prog_id_protocol
    value_ctype = MyCTypes.smallest_num

class ProgramsMap(BPFMap):
    key_ctype = MyCTypes.program_name
    value_ctype = MyCTypes.smallest_num

class PrognameProgIdMap(BPFMap):
    key_ctype = MyCTypes.program_name
    value_ctype = MyCTypes.prog_id

