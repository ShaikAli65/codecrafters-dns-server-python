import random
import asyncio
from asyncio import Future
from typing import Any

from app.config import DNSServerConfig
from app.dnsproto import DNSReply, DNSRequest, DNSRR, RCODE
import app.extractors as extractors


class DNSServer(asyncio.DatagramProtocol):
    config: DNSServerConfig
    def __init__(self) -> None:
        self.expecting_reply_from_forwarded: dict[int, Future[tuple[DNSReply, tuple[str, int]]]] = {}

    def datagram_received(self, packet: bytes, addr: tuple[str | Any, int]) -> None:
        resolved_header, h_end = extractors.header(packet)
        print("new packet ", resolved_header)

        if resolved_header.ID in self.expecting_reply_from_forwarded:
            self.process_waiting_for_reply_from_ns(resolved_header, packet, addr)

        questions, q_end = extractors.questions(packet, resolved_header)
        dns_req = DNSRequest(resolved_header, questions)

        if self.config.forwarding_addr is None:
            resp = self.arrange_response(dns_req)
            print("replying :", resp)
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
        print("forwarding", dns_request)
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
        dns_request.header.RCODE = RCODE.NOT_IMPL
        dns_request.header.ANCOUNT = len(answers)

        our_reply = DNSReply(dns_request.header, dns_request.questions, answers)
        print("replying :", our_reply)
        self.transport.sendto(bytes(our_reply), client_addr)

    def process_reply(self, packet, *, header):
        questions, end_offset = extractors.questions(packet, header)
        answers, end_offset = extractors.answers(packet, header, end_offset)
        r =  DNSReply(header, questions, answers)
        print("got reply from server :", r)
        return r

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        return super().connection_made(transport)

def create_dnsserver(server_config) -> type[asyncio.DatagramProtocol]:
    DNSServer.config = server_config
    return DNSServer
