import re
from loguru import logger

def get_clean_source_packets(packets_log_file):

    packets_log_content = packets_log_file.read()
    source_packets = [bytes(l[2:-1], 'utf-8').decode('unicode-escape')
            for l in packets_log_content.split('\n') if l]

    # logger.debug(source_packets)
    return source_packets


def get_tainted_packets(source_packets: list, token: str) -> list:
    return [packet for packet in source_packets if re.search(re.escape(token), packet)]

def get_tainted_packet(source_packets: list, token: str) -> str:
    return get_tainted_packets(source_packets, token)[0]

def get_template_from_token(source_packets: list, token: str, placeholder = '$a') -> str:

    packet = get_tainted_packet(source_packets, token)

    return re.sub(token, placeholder, packet)
