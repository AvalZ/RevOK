# RevOK



## Getting started 

`python --help`

### 

The core of RevOK is the *stub* component.
It listens for incoming requests and sends attack responses.

Responses are crafted from a *template* response and a *substitution list* containing attack payloads.
Example usage:

`python cli.py stub example.template example.substitutions`


### Automatic token deployment



You can launch the *stub* component like this:

`python cli.py server`

You can also define a specific port using the `--port` switch, for example

```
:~$ python cli.py stub --help

Usage: cli.py stub [OPTIONS] [TEMPLATE] [SUBSTITUTIONS]

    Run a stub that serves tracking responses.

Options:
    --log-file TEXT
    --port INTEGER
    --help           Show this message and exit.
```

### Enumerate tainted flows

```
:~$ python cli.py taint --help

Usage: cli.py taint [OPTIONS] PACKETS_LOG SCANNER_REPORT

    Get tainted paths between log and report.

Options:
    --token-format TEXT
    --help               Show this message and exit.

```

### Fetch attack template

```
:~$ python cli.py template --help

Usage: cli.py template [OPTIONS] PACKETS_LOG TOKEN

    Get a prebuilt template from a tainted token. The template can be used
    from the stub component.
    
    WARNING! Use the same placeholder used by the stub.

Options:
    -p, --placeholder TEXT
    --help                  Show this message and exit.
```

## Why RevOK?

In short, RevOK makes scanners explode.

This is somewhat of an obscure reference from the 1981 movie *Scanners*.

Private military company ConSec recruits "scanners" – super-powered individuals capable of telepathy and psychokinesis – and uses them in service of the company.
However, when one of ConSec's scanners demonstrates his powers at a marketing event, the volunteer – Darryl Revok – turns out to be a more powerful scanner, who causes the ConSec scanner's head to explode.

[Here](https://www.youtube.com/watch?v=qnp1jfLhtck) you can find the full scene.

## References

- [Metasploit Vulnerability (TBD)]()
- [Scanners (1981)](https://www.imdb.com/title/tt0081455/)
