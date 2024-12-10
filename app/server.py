import enum
import random
import socket
from dataclasses import dataclass, field
import struct
from app.config import DNSServerConfig
from app.dnsproto import DNSReply, DNSRequest, DnsHeader, DNSRR, Question, RCODE

import extractors
import asyncio
from asyncio import Future
from typing import Any

class DNSServer(asyncio.DatagramProtocol):
    config: DNSServerConfig
    def __init__(self, config) -> None:
        super().__init__()
        self.config = config
        self.expecting_reply_from_forwarded: dict[int, Future[tuple[DNSReply, tuple[str, int]]]] = {}

    def datagram_received(self, packet: bytes, addr: tuple[str | Any, int]) -> None:
        resolved_header, h_end = extractors.header(packet)
        print("resolved header", resolved_header)

        if resolved_header.ID in self.expecting_reply_from_forwarded:
            self.process_waiting_for_reply_from_ns(resolved_header, packet, addr)

        questions, q_end = extractors.questions(packet, resolved_header)
        dns_req = DNSRequest(resolved_header, questions)

        # print("resolved questions:", "\n".join(str(x) for x in questions), "\n")

        if self.config.forwarding_addr is None:
            # header, answers = responce(resolved_header, questions)
            # resp = header + packet[h_end: q_end] + answers
            resp = self.arrange_response(dns_req)
            self.transport.sendto(bytes(resp), addr)
        else:
            asyncio.create_task(self.handle_dns_forward(dns_req, addr))

    def arrange_response(self, dns_req: DNSRequest):
        dns_reply = DNSReply()
        dns_reply.header = dns_req.header
        dns_reply.header.QR = True

        records = []
        for question in dns_req.questions:
            ans_rr = DNSRR(question.QNAME, question.QTYPE, question.QCLASS, 0, 0, b'')
            records.append(ans_rr)

        dns_reply.header.ANCOUNT = len(records)
        dns_reply.header.RCODE = RCODE.NOT_IMPL
        dns_reply.answers = records
        dns_reply.questions = dns_req.questions

        return dns_reply

    def process_waiting_for_reply_from_ns(self, header, packet, addr):
        held_future = self.expecting_reply_from_forwarded[header.ID]
        dns_reply = self.process_reply(packet, header=header)
        held_future.set_result((dns_reply, addr))

    async def handle_dns_forward(self, dns_request: DNSRequest, client_addr):
        
        waiters = []
        for question in dns_request.questions:
            our_request = DNSRequest(dns_request.header.copy(), [question])
            our_request.header.ID = random.randint(0, 65535)
            our_request.header.QDCOUNT = 1
            self.transport.sendto(bytes(our_request), self.config.forwarding_addr)
            fut = asyncio.get_event_loop().create_future()
            self.expecting_reply_from_forwarded[our_request.header.ID] = fut
            waiters.append(fut)

        answers = []
        
        for fut in asyncio.as_completed(waiters):  # todo: add timeout
            dns_reply, addr = await fut
            dns_reply: DNSReply
            answers.extend(dns_reply.answers)

        dns_request.header.QR = True
        dns_request.header.ANCOUNT = len(answers)

        our_reply = DNSReply(dns_request.header, dns_request.questions, answers)
        self.transport.sendto(bytes(our_reply), client_addr)

    def process_reply(self, packet, *, header):
        questions, end_offset = extractors.questions(packet, header)
        answers, end_offset = extractors.answers(packet, header, end_offset)
        r =  DNSReply(header, questions, answers)
        print("got reply", r)
        return r

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        return super().connection_made(transport)

def create_dnsserver(server_config) -> type[asyncio.DatagramProtocol]:
    DNSServer.config = server_config
    return DNSServer
    
def resolve_questions(header: DnsHeader, packet: bytes):
    questions = []

    def resolve_pointer(packet, _offset):
        d = int.from_bytes(packet[_offset: _offset + 2])
        name_pointer = d & 0x3FFF
        names, no_need_of_this_offset = resolve_name(packet, name_pointer)
        _offset += 2
        return names, _offset
        
    def resolve_name(packet, _offset):
        len_to_read = packet[_offset]

        if len_to_read == 0:
            return [], _offset + 1 
        
        if (len_to_read >> 6) & 0b11:
            return resolve_pointer(packet, _offset)
        
        name = packet[_offset + 1: _offset + len_to_read + 1]
        _offset += len_to_read + 1    
        parts, _offset = resolve_name(packet, _offset)
        return [name.decode()] + parts, _offset

    offset = 12
    for _ in range(header.QDCOUNT):
        parts, ending_offset = resolve_name(packet, offset)
        q_type_class = packet[ending_offset: ending_offset + 4]
        print(parts)
        q = Question(parts, *struct.unpack("!HH", q_type_class))
        questions.insert(0, q)
        offset = ending_offset + 4

    return questions, offset

def responce(header: DnsHeader, questions: list[Question]):
    acount = 0
    resp = bytearray()
    for question in questions:
        ans_rr = DNSRR(question.QNAME, question.QTYPE, question.QCLASS, 0, 0, b'')
        resp.extend(bytes(ans_rr))
        acount += 1

    header.QR = True
    header.ANCOUNT = acount
    header.RCODE = RCODE.NOT_IMPL
    bheader = bytes(header)
    bresp = bytes(resp)
    return bheader, bresp
