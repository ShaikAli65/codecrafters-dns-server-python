import socket
from dataclasses import dataclass
import struct


MAX_DATAGRAM_SIZE = 512 * 1024

@dataclass(slots=True)
class DnsHeader:
    """
    Packet Identifier (ID)	            16 bits     A random ID assigned to query packets.
    --- Flags ---
    Query/Response Indicator (QR)	    1 bit	    1 for a reply packet, 0 for a question packet.
    Operation Code (OPCODE)	            4 bits	    Specifies the kind of query in a message.
    Authoritative Answer (AA)	        1 bit	    1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    Truncation (TC)	                    1 bit	    1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    Recursion Desired (RD)	            1 bit	    Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    Recursion Available (RA)    	    1 bit	    Server sets this to 1 to indicate that recursion is available.
    Reserved (Z)                	    3 bits      Used by DNSSEC queries
    Response Code (RCODE)	            4 bits	    Response code indicating the status of the response.
    ---
    
    Question Count (QDCOUNT)	        16 bits	    Number of questions in the Question section.
    Answer Record Count (ANCOUNT)	    16 bits	    Number of records in the Answer section.
    Authority Record Count (NSCOUNT)	16 bits	    Number of records in the Authority section.
    Additional Record Count (ARCOUNT)	16 bits	    Number of records in the Additional section.

    """
    ID: int
    QR: bool
    OPCODE: int
    AA: bool
    TC: bool
    RD: bool
    RA: bool
    Z: int
    RCODE: int
    QDCOUNT: int
    ANCOUNT: int
    NSCOUNT: int
    ARCOUNT: int

    def __bytes__(self):
        flags = (self.QR << 15) | (self.OPCODE << 11) | (self.AA << 10) | \
                (self.TC << 9) | (self.RD << 8) | (self.RA << 7) | \
                (self.Z << 4) | self.RCODE

        return struct.pack( 
            "!6H",
            self.ID,
            flags,
            self.QDCOUNT,
            self.ANCOUNT,
            self.NSCOUNT,
            self.ARCOUNT
        )


@dataclass
class DNSRR:
    """
    DNS Resource Record

    --- Resource Record ---
    @ https://en.wikipedia.org/wiki/Domain_Name_System
    NAME	    Name of the node to which this record pertains	Variable
    TYPE	    Type of RR in numeric form (e.g., 15 for MX RRs)	                                        2
    CLASS	    Class code	                                                                                2
    TTL	        Count of seconds that the RR stays valid (The maximum is 2^31 - 1, which is about 68 years)	4
    RDLENGTH	Length of RDATA field (specified in octets)	                                                2
    RDATA   	Additional RR-specific data	Variable, as per                                                RDLENGTH
    """
    NAME: bytes
    TYPE: int
    CLASS: int 
    TTL: int
    RDLENGTH: int
    RDATA: int


def resolve_header(req_data: bytes):
    """

    Packet Identifier (ID)	            16 bits     A random ID assigned to query packets.
    --- Flags ---
    Query/Response Indicator (QR)	    1 bit	    1 for a reply packet, 0 for a question packet.
    Operation Code (OPCODE)	            4 bits	    Specifies the kind of query in a message.
    Authoritative Answer (AA)	        1 bit	    1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    Truncation (TC)	                    1 bit	    1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    Recursion Desired (RD)	            1 bit	    Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    Recursion Available (RA)    	    1 bit	    Server sets this to 1 to indicate that recursion is available.
    Reserved (Z)                	    3 bits      Used by DNSSEC queries
    Response Code (RCODE)	            4 bits	    Response code indicating the status of the response.
    ---

    Question Count (QDCOUNT)	        16 bits	    Number of questions in the Question section.
    Answer Record Count (ANCOUNT)	    16 bits	    Number of records in the Answer section.
    Authority Record Count (NSCOUNT)	16 bits	    Number of records in the Authority section.
    Additional Record Count (ARCOUNT)	16 bits	    Number of records in the Additional section.

    total length 12 bytes

    """
    unpacket_tuple = struct.unpack("!6H", req_data[: 12])
    pid = unpacket_tuple[0]
    flags = unpacket_tuple[1]
    qr = flags >> 15  # bit 16
    op_code = (flags >> 11) & 0b1111  # OPCODE: bits 12-15
    aa = (flags >> 10) & 0b1          # AA: bit 11
    tc = (flags >> 9) & 0b1           # TC: bit 10
    rd = (flags >> 8) & 0b1           # RD: bit 9
    ra = (flags >> 7) & 0b1           # RA: bit 8
    z = (flags >> 4) & 0b111          # Z: bits 5-7
    rcode = flags & 0b1111            # RCODE: bits 1-4
    qdcount = unpacket_tuple[2]
    ancount = unpacket_tuple[3] 
    nscount = unpacket_tuple[4]
    arcount = unpacket_tuple[5]
    return DnsHeader(pid, qr, op_code, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

def responce(req_packet):
    return b''

def resolve_domain(packet: bytes):
    domain = packet[12: ][: packet[12:].find(b'\x00')]
    i = 1
    parts = []
    while True:
        l = int.from_bytes(domain[i - 1: i])
        parts.append(domain[i: i + l])
        i += l + 1
        if i >= len(domain):
            break
    return parts

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        packet, source = udp_socket.recvfrom(MAX_DATAGRAM_SIZE)
        print("request from", source)
        resolved_packet = resolve_header(packet)
        resolved_body = resolve_domain(packet)
        # response = responce(resolved_packet)
        print("received", packet)
        print("resolved header", resolved_packet)
        print("received extra", packet[12:])
        
        udp_socket.sendto(bytes(resolved_packet), source)


if __name__ == "__main__":
    # main()
    w = b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x03com\x00\x00\x01\x00\x01'
    resolve_domain(w)
