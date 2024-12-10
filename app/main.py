import asyncio
import socket
import sys
from app.config import DNSServerConfig
from app.server import create_dnsserver

async def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    loop = asyncio.get_event_loop()
    config = DNSServerConfig(("127.0.0.1", 2053))
    if len(sys.argv) > 2:
        print(sys.argv)
        ip, port = sys.argv[1].split(":")
        config.forwarding_addr = ip, int(port)
    
    transport, proto = await loop.create_datagram_endpoint(
        create_dnsserver(config),
        config.l_addr,
        family=config.ip_family,
        flags=config.server_flags,
    )
    
if __name__ == "__main__":
    asyncio.run(main())

    # packet = b'\xb0\xdd\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xc0\x10\x00\x01\x00\x01'
    # resp = process(packet)
    # print(resp)
