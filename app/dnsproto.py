from functools import cached_property
import struct
import enum
from dataclasses import dataclass, field
from typing import Optional

ENCODING = 'utf-8'

HEADER_LEN = 12


@dataclass(slots=True)
class DnsHeader:
    """
    
    Packet Identifier (ID)	            16 bits     A random ID assigned to query packets.

    ### Flags 
    ---

    | Name                          |    Len(bit)    |                                 Desc                                                    |  
    |:-----------------------------:|:--------------:|:---------------------------------------------------------------------------------------:|
    | Query/Response Indicator (QR)	|    1  	     | 1 for a reply packet, 0 for a question packet.                                          | 
    | Operation Code (OPCODE)	    |    4  	     | Specifies the kind of query in a message.                                               |
    | Authoritative Answer (AA)	    |    1  	     | 1 if the responding server "owns" the domain queried, i.e., it's authoritative.         |
    | Truncation (TC)	            |    1  	     | 1 if the message is larger than 512 bytes. Always 0 in UDP responses.                   |   
    | Recursion Desired (RD)	    |    1  	     | Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise. |
    | Recursion Available (RA)    	|    1  	     | Server sets this to 1 to indicate that recursion is available.                          |   
    | Reserved (Z)                	|    3           | Used by DNSSEC queries                                                                  |
    | Response Code (RCODE)	        |    4  	     | Response code indicating the status of the response.                                    |   

    ---
    
    Question Count (QDCOUNT)	        16 bits	    Number of questions in the Question section.
    Answer Record Count (ANCOUNT)	    16 bits	    Number of records in the Answer section.
    Authority Record Count (NSCOUNT)	16 bits	    Number of records in the Authority section.
    Additional Record Count (ARCOUNT)	16 bits	    Number of records in the Additional section.

    """
    ID: int = 0
    QR: bool = False
    OPCODE: int = 0
    AA: bool = False
    TC: bool = False
    RD: bool = False
    RA: bool = False
    Z: int = 0
    RCODE: int = 0
    QDCOUNT: int = 0
    ANCOUNT: int = 0
    NSCOUNT: int = 0
    ARCOUNT: int = 0

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

    def __len__(self):
        return HEADER_LEN

    def copy(self):
        return DnsHeader(
                ID = self.ID,
                QR = self.QR,
                OPCODE = self.OPCODE,
                AA = self.AA,
                TC = self.TC,
                RD = self.RD,
                RA = self.RA,
                Z = self.Z,
                RCODE = self.RCODE,
                QDCOUNT = self.QDCOUNT,
                ANCOUNT = self.ANCOUNT,
                NSCOUNT = self.NSCOUNT,
                ARCOUNT = self.ARCOUNT,
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
    NAME: list = field(default_factory=list)
    TYPE: int = 0
    CLASS: int  = 0
    TTL: int = 0
    RDLENGTH: int = 0
    RDATA: bytes = b''

    def __bytes__(self):
        start = self.raw_name + b'\x00'
        mid = struct.pack('!HHIH', self.TYPE, self.CLASS, self.TTL, self.RDLENGTH)
        end = self.RDATA
        return start + mid + end

    @property
    def raw_name(self):
        byts = bytearray()
        for name in self.NAME:
            bname = name.encode(ENCODING)
            byts.extend(len(bname).to_bytes() + bname)
        return bytes(byts)

    def copy(self):
        return DNSRR(
                NAME = self.NAME.copy(),
                TYPE = self.TYPE,
                CLASS  = self.CLASS,
                TTL = self.TTL,
                RDLENGTH = self.RDLENGTH,
                RDATA =  self.RDATA,
            )


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

    QNAME:list[str]
    QTYPE:int
    QCLASS:int

    def __bytes__(self):
        return self.raw_name + b'\x00' + self.QTYPE.to_bytes(2, 'big') + self.QCLASS.to_bytes(2, 'big')

    @cached_property
    def raw_name(self):
        byts = bytearray()
        for name in self.QNAME:
            bname = name.encode(ENCODING)
            byts.extend(len(bname).to_bytes() + bname)
        return bytes(byts)

    def __len__(self):
        return len(bytes(self))

    def copy(self):
        return Question(
            QNAME= self.QNAME.copy(),
            QTYPE= self.QTYPE,
            QCLASS= self.QCLASS,
        )

    
@dataclass
class DNSRequest:
    header: DnsHeader = DnsHeader()
    questions: list[Question] = field(default_factory=list)

    def __bytes__(self):
        questions = bytearray()
        for q in self.questions:
            questions.extend(bytes(q))
        return bytes(self.header) + bytes(questions)   
        
    def copy(self):
        return self.__class__(
            header=self.header.copy(),
            questions=[x.copy() for x in self.questions],
        )

@dataclass
class DNSReply:
    header: DnsHeader = DnsHeader()
    questions: list[Question] = field(default_factory=list)
    answers: list[DNSRR] = field(default_factory=list)

    def __bytes__(self):
        questions = bytearray()
        for q in self.questions:
            questions.extend(bytes(q))
        answers = bytearray()
        for a in self.answers:
            answers.extend(bytes(a))
        return bytes(self.header) + bytes(questions) + bytes(answers)

    def copy(self):
        return self.__class__(
            header=self.header.copy(),
            questions=[x.copy() for x in self.questions],
            answers=[x.copy() for x in self.answers],
        )
