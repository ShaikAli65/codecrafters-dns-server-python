from dataclasses import dataclass

MAX_DATAGRAM_SIZE = 512 * 1024

@dataclass
class DNSServerConfig:
    l_addr: tuple[str, int]
    ip_family: int = 0
    server_flags:int = 0
    forwarding_addr: tuple | None = None 
    timeout:int = 5


def get_args():
    ...
