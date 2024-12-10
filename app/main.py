import sys
sys.path.append("C:\\Users\\7862s\\Desktop\\codecrafters\\codecrafters-dns-server-python")

import argparse
import asyncio
from app.config import DNSServerConfig
from app.server import create_dnsserver

async def main(args):
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    loop = asyncio.get_event_loop()
    config = DNSServerConfig(("127.0.0.1", 2053))

    if args.resolver:
        ip, port = args.resolver.split(":")
        config.forwarding_addr = ip, int(port)
    
    transport, proto = await loop.create_datagram_endpoint(
        create_dnsserver(config),
        config.l_addr,
        family=config.ip_family,
        flags=config.server_flags,
    )
    await asyncio.Event().wait()

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--resolver', type=str)
    asyncio.run(main(parser.parse_args()))

    # packet = b'\xb0\xdd\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xc0\x10\x00\x01\x00\x01'
    # resp = process(packet)
    # print(resp)
