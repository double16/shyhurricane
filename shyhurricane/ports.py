from bitarray import bitarray

MAX_PORT = 65535


def parse_ports_spec(spec: list[str]) -> bitarray:
    ba = bitarray(MAX_PORT + 1)
    if not spec:
        ba.setall(True)
        return ba
    ba.setall(False)
    for el in spec:
        for part in el.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                for port in range(start, end + 1):
                    ba[port] = True
            elif part:
                ba[int(part)] = True
    if ba.count(True) == 0:
        ba.setall(True)
    return ba


def ports_to_bitfield(ports: set[int]) -> bitarray:
    ba = bitarray(MAX_PORT + 1)
    ba.setall(False)
    for port in ports:
        if 0 <= port <= MAX_PORT:
            ba[port] = True
    return ba


def bitfield_to_ports(ba: bitarray) -> list[int]:
    return [i for i, bit in enumerate(ba) if bit]


def is_subset(a_ports: bitarray, b_ports: bitarray) -> bool:
    return (a_ports & b_ports).count() == a_ports.count()
