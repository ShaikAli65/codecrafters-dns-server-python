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
