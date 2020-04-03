import click
import re
from loguru import logger
from utils import get_template_from_token, get_tainted_packets, get_tainted_packet, get_clean_source_packets
from stub import stub

from drivers import MockDriver


@click.group()
@click.pass_context
def cli(ctx):
    """

    \b
__________            ________   ____  __.
\______   \ _______  _\_____  \ |    |/ _|
 |       _// __ \  \/ //   |   \|      <  
 |    |   \  ___/\   //    |    \    |  \ 
 |____|_  /\___  >\_/ \_______  /____|__ \\
        \/     \/             \/        \/
    """
    pass

@cli.command()
@click.argument('packets_log', type=click.File('r'))
@click.argument('scanner_report', type=click.File('r'))
@click.option('--token-format', required=False)
@click.pass_context
def taint(ctx, packets_log, scanner_report, token_format):
    """
    Get tainted paths between log and report
    """
    token_format_regex = re.compile(r'[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12}', re.I)
    # token_format_regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]-{4}[0-9a-f]{4}-[0-9a-f]{12}\Z', re.I)
    if token_format:
        token_format_regex = re.compile(token_format, re.I)

    source_packets = get_clean_source_packets(packets_log)
    scanner_report_content = scanner_report.read()

    packets_log_tokens = [ token_format_regex.findall(packet) for packet in source_packets]
    packets_log_tokens = [token for sublist in packets_log_tokens for token in sublist]
    logger.debug(packets_log_tokens)
    scanner_report_tokens = token_format_regex.findall(scanner_report_content)

    common_tokens = set(packets_log_tokens) and set(scanner_report_tokens)

    # logger.info(common_tokens)

    logger.success('{} tainted path(s) found.'.format(len(common_tokens)))

    for token in common_tokens:
        # logger.success(token)
        # TODO: the [2:-1] trick removes the b' and ' from the packet. Find a cleaner way
        # TODO: find a better way to convert to escaped string

        tainted_source_packets = get_tainted_packets(source_packets, token)
        logger.debug(tainted_source_packets)

        

        for packet in tainted_source_packets:
            logger.success("Tainted source packet for token {}\n{}".format(token, packet))

@cli.command()
@click.argument('packets_log', type=click.File('r'))
@click.argument('token')
@click.option('--placeholder', '-p', default='$a')
@click.pass_context
def template(ctx, packets_log, token, placeholder):
    """
    Get a prebuilt template from a tainted token.
    The template can be used from the stub component.

    WARNING! Use the same placeholder used by the stub.
    """

    source_packets = get_clean_source_packets(packets_log)
    template = get_template_from_token(source_packets, token, placeholder)
    # logger.debug(template)

    click.echo(template)

cli.add_command(stub)
    
if __name__ == '__main__':
    cli()
