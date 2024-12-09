import enum
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

class OPCODE(enum.IntEnum):
    STANDARD = 0
    INVERSE = 1
    STATUS = 2
    FUT = enum.auto()


class RCODE(enum.IntEnum):
    NOERROR = 0
    FORMAT_ERR = 1
    SERVER_FAIL = 2
    NAME_ERR = 3
    NOT_IMPL = 4
    REFUSED = 5

@dataclass(slots=True)
class DNSRR:
    """
    DNS Resource Record

    --- Resource Record ---
    @ https://en.wikipedia.org/wiki/Domain_Name_System
    
    VAR           NAME	    Name of the node to which this record pertains	Variable
    2           TYPE	    Type of RR in numeric form (e.g., 15 for MX RRs)	                                        
    2           CLASS	    Class code	                                                                                
    4           TTL	        Count of seconds that the RR stays valid (The maximum is 2^31 - 1, which is about 68 years)	
    2           RDLENGTH	Length of RDATA field (specified in octets)	                                                
    RDLENGTH    RDATA   	Additional RR-specific data	Variable, as per                                                
    """
    raw_name: bytes
    NAME: list
    TYPE: int
    CLASS: int 
    TTL: int
    RDLENGTH: int
    RDATA: bytes

    def __bytes__(self):
        start = self.raw_name + b'\x00'
        mid = struct.pack('!HHIH', self.TYPE, self.CLASS, self.TTL, self.RDLENGTH)
        end = self.RDATA
        return start + mid + end
        

class TYPE(enum.Enum):
    A     = 1   # a host address
    NS    = 2   # an authoritative name server
    MD    = 3   # a mail destination (Obsolete - use MX)
    MF    = 4   # a mail forwarder (Obsolete - use MX)
    CNAME = 5   # the canonical name for an alias
    SOA   = 6   # marks the start of a zone of authority
    MB    = 7   # a mailbox domain name (EXPERIMENTAL)
    MG    = 8   # a mail group member (EXPERIMENTAL)
    MR    = 9   # a mail rename domain name (EXPERIMENTAL)
    NULL  = 10  # a null RR (EXPERIMENTAL)
    WKS   = 11  # a well known service description
    PTR   = 12  # a domain name pointer
    HINFO = 13  # host information
    MINFO = 14  # mailbox or mail list information
    MX    = 15  # mail exchange
    TXT   = 16  # text strings
    AXFR = 252  # A request for a transfer of an entire zone
    MAILB = 253  # A request for mailbox-related records (MB, MG or MR)
    MAILA = 254  # A request for mail agent RRs (Obsolete - see MX)
    ALL = 255  # any


class CLASS(enum.IntEnum):
    IN = 1  # the Internet
    CS = 2  # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3  # the CHAOS class
    HS = 4  # Hesiod [Dyer 87]
    ALL = 255  # any

@dataclass(slots=True)
class Question:
    raw_name: bytes
    QNAME:list[str]
    QTYPE:int
    QCLASS:int

    def __bytes__(self):
        return self.raw_name + b'\x00' + self.QTYPE.to_bytes(2, 'big') + self.QCLASS.to_bytes(2, 'big')
            
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

def resolve_domain(packet: bytes):
    e  = packet[12: ].find(b'\x00')
    domain = packet[12: ][: e]
    i = 1
    parts: list[str] = []
    while True:
        l = int.from_bytes(domain[i - 1: i])
        parts.append(str(domain[i: i + l]))
        i += l + 1
        if i >= len(domain):
            break 
    return domain, parts, packet[12: ][e + 1: ]

def resolve_questions(header: DnsHeader, packet):
    header.QDCOUNT
    *parts, everthing_else = resolve_domain(packet)
    print(*parts, everthing_else)
    # return Question(*parts, *struct.unpack('!HH',everthing_else))

def responce(header: DnsHeader, question: Question):
    resp = DNSRR(question.raw_name, question.QNAME, question.QTYPE, question.QCLASS, 0, 0, b'')
    
    header.QR = True
    header.ANCOUNT = 1
    header.RCODE = RCODE.NOT_IMPL
    # print(header,'\n', question,'\n', resp)
    return bytes(header) + bytes(question) + bytes(resp)

def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        packet, source = udp_socket.recvfrom(MAX_DATAGRAM_SIZE)
        resolved_header = resolve_header(packet)
        question = resolve_questions(resolved_header, packet)
        print("received", packet)
        # print("resolved header", resolved_header)
        print(resp := responce(resolved_header, question))
        udp_socket.sendto(resp, source)


if __name__ == "__main__":
    main()
    # w = b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'
    # print(bytes(resolve_question(w)))
