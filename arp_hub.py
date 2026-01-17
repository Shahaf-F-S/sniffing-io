# tcp_hub.py

from sniffingio import ARPHub, Sniffer, SniffSettings, PacketCallback, Packet, sendp


def arp_response(hub: ARPHub, packet: Packet):
    if not hub.collect(packet):
        return

    org = hub.get(packet).communication()

    response = org.response(payload='11:11:11:11:11:11', broadcast=False)
    # sendp(response.to_packet())

    for c in (org, response):
        print(c)


def main(address: tuple[str, int]):
    hub = ARPHub()

    settings = SniffSettings(
        count=1,
        static_filter=(
            f'arp'
            # f' and (host {address[0]}) and (port {address[1]})'
        ),
        on_packet=PacketCallback(
            lambda packet: arp_response(hub=hub, packet=packet)
        )
    )
    sniffer = Sniffer(settings=settings)
    sniffer.start()


if __name__ == '__main__':
    main(('0.0.0.0', 5555))
