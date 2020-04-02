#!/usr/bin/python3

import socket
import click
import time

from fuzzer.probabilistichttpfuzzer import prob_http_fuzzer
from loguru import logger



@click.command()
@click.argument('template', type=click.File('rb'), required=False)
@click.argument('substitutions', type=click.File('rb'), required=False)
@click.option('--log-file', required=False, multiple=True)
@click.option('--port', default=80)
# TODO: @click.option('--mode', default='all')
def server(template, substitutions, port, log_file):
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen()

    packet_logger = logger.bind(packet=True)
    packet_log_format = "{message}"

    TIMESTAMP = str(time.time()).split('.')[0]
    logger.add('full-{}.log'.format(TIMESTAMP))

    # Create debug log filter
    packet_filter = lambda record: "packet" in record["extra"]
    logger.add('packets-{}.log'.format(TIMESTAMP), filter=packet_filter, format=packet_log_format)
    for l in log_file:
        logger.add(l, filter=packet_filter, format=packet_log_format)
    logger.success("Socker listening on port {}", port)

    if template and substitutions:
        substitutions = [s.rstrip() for s in substitutions.readlines()]
        template = template.read()

        for substitution in substitutions:
            # TODO: take substitution chars as input
            current_payload = template.replace(b'$a', substitution)
            logger.info(template)
            logger.info(current_payload)
            logger.success("Current payload: {}", current_payload)
            packet_logger.debug(current_payload)
            logger.success("Accepting incoming connection")
            try:
                conn, addr = s.accept()
                logger.info("Recv data")
                data = conn.recv(1024)

                try:
                    logger.info(data.decode())
                except UnicodeDecodeError:
                    logger.info(data)

                conn.send(current_payload)
                conn.close()
            except Exception as e:
                logger.error("[-] Connection reset by peer")
                logger.error(e)

    else:
        while True:
            current_payload = prob_http_fuzzer()

            current_payload = bytes(current_payload, encoding='utf-8')

            logger.success("Current payload:\n{}", current_payload)
            packet_logger.debug(current_payload)
            logger.success("Accepting incoming connection")

            try:
                conn, addr = s.accept()
                logger.info("Recv data")
                data = conn.recv(65535)

                try:
                    logger.info(data.decode())
                except UnicodeDecodeError:
                    logger.info(data)

                conn.send(current_payload)
            except Exception as e:
                logger.error("[-] Connection reset by peer")
                logger.error(e)
            finally:
                conn.close()


if __name__ == "__main__":
    # §a§ §b§ §c§
    server()
