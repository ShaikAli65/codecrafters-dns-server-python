import socket

MAX_DATAGRAM_SIZE = 512 * 1024


def resolve_packet(req_data: bytes):
    """
    
    """


def responce(req_packet):
    return b''


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            packet, source = udp_socket.recvfrom(MAX_DATAGRAM_SIZE)
            print("request from", source)
            print("packet", packet)
            resolved_packet = resolve_packet(packet)
            response = responce(resolved_packet)
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
