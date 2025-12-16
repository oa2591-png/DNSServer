```python
import argparse
import socket
import struct

        # Useful resources to solve this lab:
        # 1. https://datatracker.ietf.org/doc/html/rfc1034
        # 2. https://datatracker.ietf.org/doc/html/rfc1035
        # 3. Kurose/Ross Book!

def dns_query(type, name, server):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)  # <-- added: prevents hanging forever
    server_address = (server, 53)  # DNS uses UDP port 53

    # Create the DNS query
    ID = 0x1234
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    header = struct.pack(
        '!HHHHHH',
        ID,
        QR << 15 | OPCODE << 11 | AA << 10 | TC << 9 | RD << 8 | RA << 7 | Z << 4 | RCODE,
        QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    )

    # Encode the QNAME
    qname_parts = name.split('.')
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('ascii') for part in qname_parts]
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00'

    # Encode the QTYPE and QCLASS
    if type == 'A':
        qtype = 1
    elif type == 'AAAA':
        qtype = 28
    else:
        raise ValueError('Invalid type')

    qclass = 1  # IN

    question = qname_encoded + struct.pack('!HH', qtype, qclass)

    # Send the query (header + question)
    message = header + question
    sock.sendto(message, server_address)

    # Receive the response from the server
    try:
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        raise TimeoutError(f"DNS query timed out contacting {server}")

    # Parse the response header
    response_header = data[:12]
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header)

    # --- added: basic DNS status checks ---
    rcode = FLAGS & 0x000F          # lowest 4 bits
    tc = (FLAGS >> 9) & 0x1         # Truncation bit

    if tc == 1:
        raise RuntimeError("DNS response is truncated (TC=1). This script would need TCP retry for full results.")

    if rcode != 0:
        rcode_map = {
            1: "Format error",
            2: "Server failure",
            3: "Name error (NXDOMAIN)",
            4: "Not implemented",
            5: "Refused",
        }
        msg = rcode_map.get(rcode, f"Unknown RCODE={rcode}")
        raise RuntimeError(f"DNS error: {msg}")
    # --------------------------------------

    # Parse the response question section (same as query)
    response_question = data[12:12+len(question)]
    if response_question != question:  # <-- changed from assert to safer error
        raise RuntimeError("Response question section did not match the query (unexpected format).")

    if ANCOUNT == 0:  # <-- added: don’t silently return None
        raise RuntimeError("DNS response contained 0 answers.")

    # Parse the response answer section
    response_answer = data[12+len(question):]
    offset = 0
    for _ in range(ANCOUNT):
        # Parse the name
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1
            if length == 0:
                break
            elif length & 0xc0 == 0xc0:
                # Pointer
                pointer = struct.unpack('!H', response_answer[offset-1:offset+1])[0] & 0x3fff
                offset += 1
                name_parts.append(parse_name(data, pointer))
                break
            else:
                # Label
                label = response_answer[offset:offset+length].decode('ascii')
                offset += length
                name_parts.append(label)
        name = '.'.join(name_parts)

        # Parse the type, class, TTL, and RDLENGTH
        rtype, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset:offset+10])
        offset += 10

        # Parse the RDATA
        rdata = response_answer[offset:offset+rdlength]
        offset += rdlength

        if rtype == 1:
            ipv4 = socket.inet_ntop(socket.AF_INET, rdata)
            print(f'{name} has IPv4 address {ipv4}')
            return ipv4
        elif rtype == 28:
            ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(f'{name} has IPv6 address {ipv6}')
            return ipv6

    # If we got here, there were answers but none matched A/AAAA as requested
    raise RuntimeError("DNS response had answers, but none matched the requested record type.")

def parse_name(data, offset):
    name_parts = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        elif length & 0xc0 == 0xc0:
            pointer = struct.unpack('!H', data[offset-1:offset+1])[0] & 0x3fff
            offset += 1
            name_parts.append(parse_name(data, pointer))
            break
        else:
            label = data[offset:offset+length].decode('ascii')
            offset += length
            name_parts.append(label)
    return '.'.join(name_parts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send a DNS query and parse the reply.')
    parser.add_argument('--type', choices=['A', 'AAAA'], required=True, help='the type of address requested')
    parser.add_argument('--name', required=True, help='the host name being queried')
    parser.add_argument('--server', required=True, help='the IP address of the DNS server to query')
    args = parser.parse_args()

    result = dns_query(args.type, args.name, args.server)
```

If you want, tell me an example command you’re running (name + server), and I’ll sanity-check expected behavior (timeout vs answer vs NXDOMAIN).
