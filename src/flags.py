class flags:
    def __init__(self):
        self.has_SYN = 0
        self.has_response = 0
        self.has_FIN = 0
        self.has_RST = 0

    def update(self, tcp_packet):
        flags = int(tcp_packet.flags)

        if flags & 0x02 and not (flags & 0x10):  # SYN
            self.has_SYN = 1

        if flags & 0x12 == 0x12:  #SYNACK
            self.has_response = 1

        if flags & 0x01:  #FIN
            self.has_FIN = 1

        if flags & 0x04: #RST
            self.has_RST = 1

    def get_flag_SF(self):
        return 1 if self.has_SYN and self.has_response and self.has_FIN and not self.has_RST else 0

    def get_flag_S0(self):
        return 1 if self.has_SYN and not self.has_response else 0

    def get_flag_RSTR(self):
        return self.has_RST