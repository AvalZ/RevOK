import re
import random
import uuid

from loguru import logger

RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')
START_SYMBOL = '<start>'

def nonterminals(expansion):
    if isinstance(expansion, tuple):
        expansion = expansion[0]
    return re.findall(RE_NONTERMINAL, expansion)

def is_nonterminal(s):
        return re.match(RE_NONTERMINAL, s)

HTTP_RESPONSE_GRAMMAR = {
        '<start>': ["<statusline><headers>\r\n<body>"],
        '<statusline>': ["<httpversion> <status>\r\n"],
        '<httpversion>': [
            # 'HTTP/0.9',
            'HTTP/1.0',
            'HTTP/1.1'
            ],
        '<status>': [
            '<informational>',
            '<success>',
            '<redirection>',
            '<clienterror>',
            '<servererror>',
            ],
        '<informational>': [
            "100 Continue",
            "101 Switching Protocols",
            ],
        '<success>': [
            "200 OK",
            "201 Created",
            "202 Accepted",
            "203 Non-Authoritative Information",
            "204 No Content",
            "205 Reset Content",
            "205 Partial Content",
            "200 <uuid>",
            ],
        '<redirection>': [
            "300 Multiple Choices",
            "301 Moved Permanently",
            "302 Found",
            "303 See Other",
            "304 Not Modified",
            "305 Use Proxy",
            "307 Temporary Redirect",
            "301 <uuid>",
            "302 <uuid>",
            ],
        '<clienterror>': [
            "400 Bad Request",
            "401 Unauthorized",
            "402 Payment Required",
            "403 Forbidden",
            "404 Not Found",
            "405 Method Not Allowed",
            "406 Not Acceptable",
            "407 Proxy Authentication Required",
            "408 Request Time-out",
            "409 Conflict",
            "410 Gone",
            "411 Length Required",
            "412 Precondition Failed",
            "413 Request Entity Too Large",
            "414 Request-URI Too Large",
            "415 Unsupported Media Type",
            "416 Requested range not satisfiable",
            "417 Expectation Failed",
            "400 <uuid>",
            ],
        '<servererror>': [
            "500 Internal Server Error",
            "501 Not Implemented",
            "502 Bad Gateway",
            "503 Service Unavailable",
            "504 Gateway Time-out",
            "505 HTTP Version not supported",
            "500 <uuid>",
            ],
        '<headers>': [
            '<serverheader>\r\n<header>\r\n',
            '<serverheader>\r\n<header>\r\n<headers>',
            ],
        '<body>': [
                "<uuid>"],
        '<header>': [
                'Set-Cookie: PHPSESSID=<uuid>',
                'Content-Security-Policy: <uuid>',
                'Refresh: <uuid>',
                'X-Powered-By: <uuid>',
                'X-Request-ID: <uuid>',
                'X-UA-Compatible: <uuid>',
                'X-XSS-Protection: <uuid>',
                'Accept-Patch: <uuid>',
                'Accept-Ranges: <uuid>',
                'Age: <uuid>',
                'Allow: <uuid>',
                'Alt-Svc: <uuid>',
                'Cache-Control: <uuid>',
                'Connection: <uuid>',
                'Content-Disposition: <uuid>',
                'Content-Encoding: <uuid>',
                'Content-Language: <uuid>',
                'Content-Length: <uuid>',
                'Content-Location: <uuid>',
                'Content-Range: <uuid>',
                'Content-Type: <uuid>',
                'Date: <uuid>',
                'Delta-Base: <uuid>',
                'ETag: <uuid>',
                'Expires: <uuid>',
                'IM: <uuid>',
                'Last-Modified: <uuid>',
                'Link: <uuid>',
                'Location: <uuid>',
                'Pragma: <uuid>',
                'Proxy-Authenticate: <uuid>',
                'Public-Key-Pins: <uuid>',
                'Retry-After: <uuid>',
                'Set-Cookie: <uuid>',
                'Strict-Transport-Security: <uuid>',
                'Trailer: <uuid>',
                'Transfer-Encoding: <uuid>',
                'Tk: <uuid>',
                'Upgrade: <uuid>',
                'Vary: <uuid>',
                'Via: <uuid>',
                'Warning: <uuid>',
                'WWW-Authenticate: <uuid>',
                ],
        '<serverheader>':
                ['Server: <uuid>',],
        '<uuid>': [
                # '<fhex><fhex>-<fhex>',
                '<fhex><fhex>-<fhex>-<fhex>-<fhex>-<fhex><fhex><fhex>',
            ],
        '<fhex>': ['<hex><hex><hex><hex>'],
        '<hex>': [ 'a', 'b', 'c', 'd', 'e', 'f', '0','1','2','3','4','5','6','7','8','9' ],
        }


def simple_grammar_fuzzer(grammar, start_symbol=START_SYMBOL,
                          max_nonterminals=10, max_expansion_trials=100,
                          log=False):
    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        logger.debug(term)
        logger.debug(nonterminals(term))
        logger.debug(symbol_to_expand)
        # print("Symbol to expand:", symbol_to_expand)
        expansions = grammar[symbol_to_expand]
        # print("Expansions:", expansions)
        expansion = random.choice(expansions)
        # print("Chosen espansion:", expansion)
        new_term = term.replace(symbol_to_expand, expansion, 1)
        # print("New term:", new_term)

        if len(nonterminals(new_term)) < max_nonterminals:
            # print("Term", term)
            term = new_term
            # print("Term", term)
            if log:
                print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= max_expansion_trials:
                raise ExpansionError("Cannot expand " + repr(term))
    return term


def http_fuzzer():
    return simple_grammar_fuzzer(grammar=HTTP_RESPONSE_GRAMMAR, max_nonterminals=50, log=False)

class ExpansionError(Exception):
    pass

if __name__ == '__main__':
    # print(nonterminals(random.choice(HTTP_RESPONSE_GRAMMAR['<start>'])))
    print(simple_grammar_fuzzer(grammar=HTTP_RESPONSE_GRAMMAR, max_nonterminals=50, log=False))
