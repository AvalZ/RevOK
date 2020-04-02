import re
import random

from numpy.random.mtrand import choice

RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')
START_SYMBOL = '<start>'

"""

Frequencies are computed according to 

A. Lavrenovs and G. Visky,
"Investigating HTTP response headers for the classification of devices on the Internet",
2019 IEEE 7th IEEE Workshop on
Advances in Information, Electronic and Electrical Engineering (AIEEE),
Liepaja, Latvia, 2019, pp. 1-6.

and

A. Lavrenovs and F. J. R. Melón,
"HTTP security headers analysis of top one million websites",
2018 10th International Conference on
Cyber Conflict (CyCon),
Tallinn, 2018, pp. 345-370.
"""

HTTP_PROB_GRAMMAR = {
    '<start>': [
        ["<statusline><headers>\r\n<body>", 1]
    ],
    '<statusline>': [
        ["<httpversion> <status>\r\n", 1]
    ],
    '<httpversion>': [
        ['HTTP/1.0', .5],
        ['HTTP/1.1', .5],
    ],
    '<status>': [
        ['<informational>', 0],
        ['<success>', .554],
        ['<redirection>', .4275],
        ['<clienterror>', .0125],
        ['<servererror>', .006],
    ],
    '<informational>': [
        ["100 Continue", .25],
        ["101 Switching Protocols", .25],
        ["100 <uuid>", .25],
        ["101 <uuid>", .25],
    ],
    '<success>': [
        ["200 OK", .5],
        ["200 <uuid>", .5],
    ],
    '<redirection>': [
        ["301 Moved Permanently", .7720 / 2],
        ["302 Found", .2280 / 2],
        ["301 <uuid>", .7720 / 2],
        ["302 <uuid>", .2280 / 2],
    ],
    '<clienterror>': [
        ["403 Forbidden", .52 / 2],
        ["404 Not Found", .48 / 2],
        ["403 <uuid>", .52 / 2],
        ["404 <uuid>", .48 / 2],
    ],
    '<servererror>': [
        ["500 Internal Server Error", .5],
        ["500 <uuid>", .5],
    ],
    '<headers>': [
        ['<serverheader><xpoweredby><location><setcookie>'
            + '<xcontenttype><xaspnetversion><xaspnetmvcversion><xvarnish>'
            + '<stricttransportsecurity><contentsecuritypolicy><xxssprotection>'
            + '<xframeoptions>', 1],
    ],
    '<xframeoptions>': [
        ['<xframeoptionsvalue>\r\n', .5],
        ['', .5],
    ],
    '<xframeoptionsvalue>': [
        ['X-Frame-Options: deny', .33],
        ['X-Frame-Options: allow-from <uuid>', .34],
        ['X-Frame-Options: sameorigin', .33],
    ],
    '<xxssprotection>': [
        ['<xxssprotectionvalue>\r\n', .5],
        ['', .5],
    ],
    '<xxssprotectionvalue>': [
        ['X-XSS-Protection: 0', .16],
        ['X-XSS-Protection: 1', .17],
        ['X-XSS-Protection: <uuid>', .17],
        ['X-XSS-Protection: 1; mod=block', .16],
        ['X-XSS-Protection: 1; mod=<uuid>', .17],
        ['X-XSS-Protection: 1; report=<uuid>', .17],
    ],
    '<stricttransportsecurity>': [
        ['<stricttransportsecurityvalue>\r\n', .5],
        ['', .5],
    ],
    '<stricttransportsecurityvalue>': [
        ['Strict-Transport-Security: max-age=<digit><digit><digit><digit>', .111],
        ['Strict-Transport-Security: max-age=<digit><digit><digit><digit>; preload', .111],
        ['Strict-Transport-Security: max-age=<digit><digit><digit><digit>; includeSubDomains', .111],
        ['Strict-Transport-Security: max-age=<digit><digit><digit><digit>; includeSubDomains; preload', .111],
        ['Strict-Transport-Security: max-age=<uuid>', .112],
        ['Strict-Transport-Security: max-age=<digit><digit><digit><digit>; <uuid>', .111],
        ['Strict-Transport-Security: max-age=<uuid>; preload', .111],
        ['Strict-Transport-Security: max-age=<uuid>; includeSubDomains', .111],
        ['Strict-Transport-Security: max-age=<uuid>; includeSubDomains; preload', .111],
    ],
    '<contentsecuritypolicy>': [
            ['Content-Security-Policy: default-src <uuid>\r\n', .5],
            ['', .5],
    ],
    '<xaspnetversion>': [
        ['X-AspNet-Version: <uuid>\r\n', .5],
        ['', .5],
    ],
    '<xaspnetmvcversion>': [
        ['X-AspNetMvc-Version: <uuid>\r\n', .5],
        ['', .5],
    ],
    '<xvarnish>': [
        ['X-Varnish: <uuid>\r\n', .5],
        ['', .5],
    ],
    '<xcontenttype>': [
        ['', .86],
        ['X-Content-Type-Options: nosniff\r\n', .07],
        ['X-Content-Type-Options: <uuid>\r\n', .07],
    ],
    '<body>': [
        ["<uuid>", 1]
    ],
    '<location>': [
        ['', 0.37],
        ['Location: <uuid>\r\n', (1 - 0.37) / 2],
        ['Location: <locationlink>\r\n', (1 - 0.37) / 2],
    ],
    '<locationlink>': [
            ['https://<uuid>/', 0.5155389686916363],
            ['http://<uuid>:8899', 0.16728032918655752],
            ['https://<uuid>:8090', 0.13519687898008015],
            ['http://<uuid>/login.lp', 0.06457265884473522],
            ['/nocookies.html', 0.05926549648160242],
            ['/cookiechecker?uri=/', 0.058145667815388345],
            ],
    '<setcookie>': [
            ['Set-Cookie: <setcookievalue>\r\n', .175],
            ['', .825],
    ],
    '<setcookievalue>': [
        # FIXME: all uuids, since no session is created anyway
        ['__cfduid=<uuid>', .471],
        ['PHPSESSID=<uuid>', .394],
        ['ASP.NET_SessionId=<uuid>', .087],
        ['JSESSIONID=<uuid>', .048],
    ],
    '<serverheader>': [
        ['Server: <uuid>\r\n', .475],
        ['Server: <servertype>/<uuid>\r\n', .475],
        ['', .05],
    ],
    '<xpoweredby>': [
        ['X-Powered-By: <langtype>\r\n', .24],
        ['X-Powered-By: <uuid>\r\n', .24],
        ['', .52],
    ],
    '<servertype>': [
        ['Apache', .34752161561695627],
        ['nginx', .23724219857496398],
        ['AkamaiGHost', .22815961395521514],
        ['Microsoft-IIS', .1446213483742607],
        ['lighttpd', .04245522347860392],
    ],
    '<langtype>': [
        ['php', .5],
        ['rails', .5],
    ],
    '<serverversion>': [
        ['<digit>.<digit>.<digit>', .1],
        ['<uuid>', .9],
    ],
    '<uuid>': [
        ['<fhex><fhex>-<fhex>-<fhex>-<fhex>-<fhex><fhex><fhex>', 1],
    ],
    '<fhex>': [
            ['<hex><hex><hex><hex>', 1]
        ],
    '<hex>': [
        ['<hexchar>', 6 / 16],
        ['<digit>', 10 / 16],
    ],
    '<hexchar>': [
        ['a', 1 / 6], ['b', 1 / 6], ['c', 1 / 6], ['d', 1 / 6], ['e', 1 / 6], ['f', 1 / 6],
    ],
    '<digit>': [
        ['0', 1 / 10], ['1', 1 / 10], ['2', 1 / 10], ['3', 1 / 10], ['4', 1 / 10],
        ['5', 1 / 10], ['6', 1 / 10], ['7', 1 / 10], ['8', 1 / 10], ['9', 1 / 10],
    ],
}


def expand_non_terminal(nonterm, grammar):
    expansions = grammar[nonterm]
    values = [e[0] for e in expansions]
    weights = [e[1] for e in expansions]
    # print(nonterm)
    chosen = choice(values, 1, p=weights)[0]
    return chosen


def prob_grammar_fuzzer(grammar, start_symbol=START_SYMBOL,
                        max_nonterminals=10, max_expansion_trials=100,
                        log=False):
    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansion = expand_non_terminal(symbol_to_expand, grammar)
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
                raise Exception("Cannot expand " + repr(term))
    return term


def nonterminals(expansion):
    if isinstance(expansion, tuple):
        expansion = expansion[0]
    return re.findall(RE_NONTERMINAL, expansion)

def prob_http_fuzzer():
    return prob_grammar_fuzzer(HTTP_PROB_GRAMMAR, max_nonterminals=50)

if __name__ == "__main__":
    print(prob_http_fuzzer())


    print(res)
