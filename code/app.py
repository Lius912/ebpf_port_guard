import sys
import ctypes
from bcc import libbcc
from socket import inet_pton, AF_INET, inet_ntoa
import os
import argparse
import json

from ebpf_maps import *

maps_path = "/sys/fs/bpf"

# ports_map_path = os.path.join(maps_path, "ports_map")
# pid_prog_id_map_path = os.path.join(maps_path, "pid_prog_id_map")


config_path = "ebpf_port_guard\code\config_copy.json"
config_path = "config_copy.json"

# programs_map_path = os.path.join(maps_path, "programs_map")
# programs_map = ProgramsMap(programs_map_path)

prog_id_ports_map_path = os.path.join(maps_path, "prog_id_ports_map")
prog_id_ports_map = ProgIdPortsMap(prog_id_ports_map_path)

progname_prog_id_map_path = os.path.join(maps_path, 'progname_prog_id_map')
progname_prog_id_map = PrognameProgIdMap(progname_prog_id_map_path)

our_maps = {"prog_id_ports_map": prog_id_ports_map}


def load_maps(config):
    prog_id = 0
    print("Adding config entries")
    for entry in config:
        # for port in entry["ingress"]["ports"]:
        #     ingress_prog_id_ports_map.add_entry((prog_id, port), 1)
        # for protocol in entry["ingress"]["protocols"]:
        #     ingress_prog_id_protocols_map.add_entry((prog_id, protocol), 1)

        assert len(entry['name']) <= 255
        to_send = []
        for char in entry['name']:
            to_send.append(ord(char))
        
        progname_prog_id_map.add_entry(bytes(to_send), prog_id)
        
        for port in entry["ports"]:
           prog_id_ports_map.add_entry((prog_id, port), 1)

        prog_id += 1

if __name__ == "__main__":
    # parser = argparse
    # if len(sys.argv) < 2:
    #     print(f"Usage: {sys.argv[0]} <action> <args>")
    #     print("Actions: add <ip> <value>, delete <ip>, show")
    #     sys.exit(1)

    # map_fd = get_map_fd(commands_map_path)



    if len(sys.argv) == 1:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        load_maps(config)
        print()
        # print("adding cookies pids")
        # cookies_pid_map.add_entry(23, 201)
        # print()
        
        print("Maps are successfully loaded")
        sys.exit(0)

    map_name = sys.argv[1]
    action = sys.argv[2]
    selected_map = our_maps[map_name]
    if action == "show" and len(sys.argv) == 3:
        selected_map.show_map()
    elif action == "add" and len(sys.argv) == 5:
        key, value = int(sys.argv[3]), int(sys.argv[4])
        selected_map.add_entry(key, value)
    elif action == "delete" and len(sys.argv) == 4:
        key = int(sys.argv[3])
        selected_map.delete_entry(key)
    else:
        print(f"Invalid usage. Usage: {sys.argv[0]} <action> <args>")
        print("Actions: add <key> <value>, delete <key>, show")
        sys.exit(1)


