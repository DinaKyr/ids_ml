from scapy.all import IP, TCP , UDP,ICMP
from collections import defaultdict
from flags import flags


SERVICE_PORTS = {
    # TCP/UDP ports
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    79: "finger",
    80: "http",
    109: "pop_2",
    110: "pop_3",
    111: "sunrpc",
    113: "auth",
    119: "nntp",
    123: "ntp_u",
    137: "netbios_ns",
    138: "netbios_dgm",
    139: "netbios_ssn",
    143: "imap4",
    150: "sql_net",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    443: "https",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    548: "afp",
    631: "cups",
    873: "rsync",

    # Rare KDD labels (TCP/UDP)
    7: "eco_i",      # Echo
    9: "discard",
    11: "systat",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    37: "time",
    43: "whois",

    #ICMP types
    0: 'eco_i',      # Echo Reply
    3: 'urp_i',      # Destination Unreachable
    8: 'eco_i',      # Echo Request
    11: 'tim_i'      # Time Exceeded
}




class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.host_history = defaultdict(list)
        self.host_service_history = defaultdict(lambda: defaultdict(list))
        self.flow_stats = defaultdict(lambda: {
            'start_time': None,
            'last_time': None,
            'dst_bytes':0,
            'tcp_flags': flags()
            
        })

    def analyze_packet(self, packet):
        if IP not in packet or not (TCP in packet or UDP in packet or ICMP in packet):
            return

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        pkt_len = len(packet)
        current_time = packet.time
        window=2.0 #for count + same_srv_rate


        #tcp udp have ports icmp has type code
        #determine flow key
        if TCP in packet or UDP in packet:
            layer = TCP if TCP in packet else UDP
            sport = packet[layer].sport
            dport = packet[layer].dport

            flow_key = (ip_src, ip_dst, sport, dport)
            #reverse_key = (ip_dst, ip_src, dport, sport)
        else:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            flow_key = (ip_src, ip_dst, icmp_type, icmp_code)
            #reverse_key = (ip_dst, ip_src, icmp_type, icmp_code)

        stats = self.flow_stats[flow_key]
        if not stats['start_time']:
            stats['start_time'] = current_time
        stats['last_time'] = current_time

        stats['count'] = self.update_host_history(ip_src, current_time, window)

        # Count only bytes from original source -> destination
        self.update_dst_bytes(flow_key, stats, ip_src, ip_dst, pkt_len, packet)

        service = self.detect_service(packet)
        stats['service']= service


        stats['same_srv_rate']= self.update_same_service_rate(ip_src, service, current_time, window)

        self.update_TCP_flags(packet, stats)
        return self.extract_features(packet, stats)
        
    def detect_service(self, packet):
        if TCP in packet or UDP in packet:
            layer = TCP if TCP in packet else UDP
            dport = packet[layer].dport

            if 6000 <= dport <= 6999:
                return "private"
            if dport in SERVICE_PORTS:
                return SERVICE_PORTS[dport]

            return "other"
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            if icmp_type in SERVICE_PORTS:
                return SERVICE_PORTS[icmp_type]
            return "icmp"
        
        return "other"
        

    def update_host_history(self, ip, current_time, window):
    # Create history for new IP if it doesn't exist
        if ip not in self.host_history:
            self.host_history[ip] = []

        # Add current packet timestamp
        self.host_history[ip].append(current_time)

        # Keep only timestamps inside the time window
        self.host_history[ip] = [
            ts for ts in self.host_history[ip]
            if current_time - ts <= window
        ]

        # Return the updated count
        return len(self.host_history[ip])

    def update_dst_bytes(self, flow_key, stats, ip_src, ip_dst, pkt_len, packet):
        # flow_key: (src_ip, dst_ip, src_port, dst_port)
        if ip_src == flow_key[0] and ip_dst == flow_key[1]:
            stats['dst_bytes'] += pkt_len

            # debug info
            if TCP in packet:
                print("flow:", flow_key, "packet flags:", packet[TCP].flags,
                    "dst_bytes:", stats['dst_bytes'])
            else:
                print("flow:", flow_key, "other packet",
                    "dst_bytes:", stats['dst_bytes'])

            return True  # update happened

        return False  # direction does not match → ignore bytes
    

    def update_same_service_rate(self, ip, service, current_time, window):
        # Record current packet timestamp
        self.host_service_history[ip][service].append(current_time)

        # Keep only events within the sliding window
        self.host_service_history[ip][service] = [
            t for t in self.host_service_history[ip][service]
            if current_time - t <= window
        ]

        # All connections from this host (already cleaned elsewhere)
        total_connections = len(self.host_history[ip])

        # Service-specific count
        same_service_connections = len(self.host_service_history[ip][service])

        # Calculate rate
        return same_service_connections / total_connections if total_connections > 0 else 0.0



    def update_TCP_flags(self, packet, stats):
        if TCP in packet:
            stats['tcp_flags'].update(packet[TCP])


            # self.flow_stats[flow_key]['tcp_flags'].update(packet[TCP])
            stats['flag_SF'] =stats['tcp_flags'].get_flag_SF()
            stats['flag_S0'] = stats['tcp_flags'].get_flag_S0()
            stats['flag_RSTR'] = stats['tcp_flags'].get_flag_RSTR()
            print(packet[TCP].flags)
        else:
            # For non-TCP packets, set flags to 0
            stats['flag_SF'] = 0
            stats['flag_S0'] = 0
            stats['flag_RSTR'] = 0


    def extract_features(self, packet, stats):
        
        return {
            'service': stats['service'],
            'dst_bytes': stats['dst_bytes'],
            'count': stats['count'],
            'same_srv_rate': stats['same_srv_rate'],
            'protocol_type_icmp': 1 if ICMP in packet else 0,
            'protocol_type_tcp': 1 if TCP in packet else 0,
            'flag_RSTR': stats['flag_RSTR'],
            'flag_S0': stats['flag_S0'],
            'flag_SF': stats['flag_SF']

        }
    
