import struct
from dnsproto import DNSRR, DnsHeader, Question, HEADER_LEN


def header(req_data: bytes):
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
    return DnsHeader(pid, qr, op_code, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount), 12


def _resolve_pointer(packet, _offset):
    d = int.from_bytes(packet[_offset: _offset + 2])
    name_pointer = d & 0x3FFF
    names, no_need_of_this_offset = _resolve_name(packet, name_pointer)
    _offset += 2
    return names, _offset

    
def _resolve_name(packet, _offset):
    len_to_read = packet[_offset]

    if len_to_read == 0:
        return [], _offset + 1 
    
    if (len_to_read >> 6) & 0b11:
        return _resolve_pointer(packet, _offset)
    
    name = packet[_offset + 1: _offset + len_to_read + 1]
    _offset += len_to_read + 1    
    parts, _offset = _resolve_name(packet, _offset)
    return [name.decode()] + parts, _offset


def questions(packet: bytes, header: DnsHeader):

    offset = len(header)
    questions = []

    for _ in range(header.QDCOUNT):
        parts, ending_offset = _resolve_name(packet, offset)
        q_type_class = packet[ending_offset: ending_offset + 4]
        print(parts)
        q = Question(parts, *struct.unpack("!HH", q_type_class))
        questions.insert(0, q)
        offset = ending_offset + 4

    return questions, offset

def answers(packet: bytes, header: DnsHeader, offset):
    answers = []

    for _ in range(header.ANCOUNT):
        parts, ending_offset = _resolve_name(packet, offset) 
        mid = struct.unpack('!HHIH',packet[ending_offset: ending_offset + 10])
        ending_offset += 10
        ans = DNSRR(parts, *mid)
        ans.RDATA = packet[ending_offset: ending_offset + ans.RDLENGTH]
        answers.append(ans)
        
    return answers, ending_offset

__all__ = 'header', 'questions', 'answers'
