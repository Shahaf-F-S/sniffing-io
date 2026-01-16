
from sniffingio import TCPHub, Sniffer, SniffSettings, PacketCallback, Packet, sendp


def tcp_double_pa_r(hub: TCPHub, packet: Packet):
    if not hub.collect(packet):
        return

    org = hub.get(packet).current_communication()

    pa_to_src = org.response(flags='PA', payload=b'hello')
    sendp(pa_to_src.to_packet())

    r_to_src = pa_to_src.next(flags='R')
    sendp(r_to_src.to_packet())

    pa_to_dst = org.next(flags='PA', payload=b'hello')
    sendp(pa_to_dst.to_packet())

    r_to_dst = pa_to_dst.next(flags='R')
    sendp(r_to_dst.to_packet())

    for c in (org, pa_to_src, r_to_src, pa_to_dst, r_to_dst):
        print(c)


def main(address: tuple[str, int]):
    hub = TCPHub()

    settings = SniffSettings(
        count=1,
        static_filter=f'tcp and (host {address[0]}) and (port {address[1]})',
        on_packet=PacketCallback(
            lambda packet: tcp_double_pa_r(hub=hub, packet=packet)
        )
    )
    sniffer = Sniffer(settings=settings)
    sniffer.start()


if __name__ == '__main__':
    main(('0.0.0.0', 5555))
