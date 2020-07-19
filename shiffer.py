#!/usr/bin/env python3
import asyncio
from socket import socket, AF_PACKET, SOCK_DGRAM

import argparse

ETH_P_ALL = 0x0003


def stop():
    print('\nstopping sniffer...')
    loop = asyncio.get_event_loop()
    loop.stop()
    print('sniffer stopped')
    exit()


class RawProtocol:

    def connection_made(self, transport:asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data, source):
        #ifacename, protocol_type, in or out, packet_type ETHERNET, hwaddr
        if_name, proto, direction, pk_type, src_mac = source
        message = data.hex()
        mac_str = ':'.join(hex(i)[2:].upper() for i in src_mac)
        print('{}:\n{}\n\n'.format(mac_str, message))

    def error_received(self, err):
        print('ERROR!\n{}: {}'.format(err.__class__.__name__, str(err)))
        stop()

    def connection_lost(self, exc): 
        print('device not available now')
        stop()


async def start_sniff(if_name):
    loop = asyncio.get_event_loop()
    raw_sock = socket(AF_PACKET, SOCK_DGRAM)
    raw_sock.bind((if_name, ETH_P_ALL))
    raw_reader, raw_writer = await loop.create_datagram_endpoint(
        RawProtocol, 
        sock=raw_sock
    )


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Simple asyncio sniffer', add_help=True)
    parser.add_argument('-i', '--ifname', default=None, help='Name of interface which sniffer will run on')
    namespace = parser.parse_args()
    ifname = namespace.ifname

    if not ifname:
        print("Interface name don't specified")
        exit()

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_sniff(ifname))
        loop.run_forever()
    except KeyboardInterrupt:
        stop()
    except Exception as e:
        print('ERROR!\n{}: {}'.format(e.__class__.__name__, str(e)))
        stop()
