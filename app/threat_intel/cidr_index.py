import ipaddress


class CIDRIndex:
    def __init__(self):
        self._networks = []  # list of (network_int, prefix_len, metadata)
        self._exact_ips = {}  # hash map for single /32 IPs
        self._built = False

    def add(self, cidr: str, metadata: dict):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        if net.version != 4:
            return  # IPv4 only for now
        if net.prefixlen == 32:
            self._exact_ips[int(net.network_address)] = metadata
        else:
            self._networks.append((int(net.network_address), net.prefixlen, metadata))
        self._built = False

    def build(self):
        self._networks.sort(key=lambda x: (-x[1], x[0]))
        self._built = True

    def lookup(self, ip: str) -> list[dict]:
        if not self._built:
            self.build()
        try:
            ip_int = int(ipaddress.ip_address(ip))
        except ValueError:
            return []
        matches = []
        if ip_int in self._exact_ips:
            matches.append(self._exact_ips[ip_int])
        for net_int, prefix_len, meta in self._networks:
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            if (ip_int & mask) == (net_int & mask):
                matches.append(meta)
        return matches

    @property
    def size(self) -> int:
        return len(self._exact_ips) + len(self._networks)
