#!/usr/bin/env python

import argparse
from dataclasses import dataclass, asdict
import enum
from ipaddress import ip_address, IPv4Address, IPv6Address
import os
from pprint import pformat
import json
from pathlib import Path
import requests
import signal
import subprocess
import sys
from typing import (
    Any,
    Dict,
    IO,
    Optional,
    Sequence,
    Set,
    Union,
)

# from systemd import notify

CompletedProcess = subprocess.CompletedProcess[Any]
Popen = subprocess.Popen[Any]

_FILE = Union[None, int, IO[Any]]
PathString = Union[Path, str]
IPAddress = Union[IPv4Address, IPv6Address]


class RecordType(enum.Enum):
    A = "A"
    AAAA = "AAAA"
    NS = "NS"
    ALIAS = "ALIAS"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"

    def __str__(self) -> str:
        return self.value


@dataclass
class Record:
    name: str
    type: RecordType
    content: str | IPAddress | None
    id: int = 0
    ttl: int = 60
    prio: int = 0
    notes: str = ""

    def __post_init__(self) -> None:
        self.id = int(self.id)
        self.type = RecordType(self.type)

    def __hash__(self) -> int:
        return self.id

    @property
    def asdict(self) -> Dict[str, str]:
        ret = asdict(self)
        ret['id'] = f"{self.id}"
        ret['type'] = f"{self.type}"
        ret['content'] = f"{self.content}"
        ret['ttl'] = f"{self.ttl}"
        ret['prio'] = f"{self.prio}"
        ret['notes'] = self.notes
        return ret

    def asjson(self):
        return json.dumps(self.asdict)


@dataclass
class apiConfig:
    endpoint: str
    apikey: str
    secretapikey: str

    @property
    def as_json(self) -> str:
        return json.dumps(asdict(self))


def get_records(args: argparse.Namespace, api_config: apiConfig):
    """
    grab all the records so we know which ones to delete to make room for our
    record.
    Also checks to make sure we've got the right domain
    """
    endpoint = api_config.endpoint + '/dns/retrieve/' + args.root
    all_records = json.loads(
        requests.post(endpoint, data=api_config.as_json).text
    )
    if all_records["status"] == "ERROR":
        print(
            'Error getting domain.'
            'Check to make sure you specified the correct domain, '
            'and that API access has been switched on for this domain.'
        )
        sys.exit()
    return all_records['records']


def foreground() -> None:
    """
    If we're connected to a terminal, put the process in a new process group
    and make that the foreground process group so that
    only this process receives SIGINT.
    """
    if sys.stdin.isatty():
        os.setpgrp()
        old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.tcsetpgrp(0, os.getpgrp())
        signal.signal(signal.SIGTTOU, old)


def run(
    cmdline: Sequence[PathString],
    check: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    env: Dict[str, PathString] = {},
    **kwargs: Any,
) -> CompletedProcess:

    cmdline = [os.fspath(x) for x in cmdline]

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    env = dict(
        PATH=os.environ["PATH"],
        TERM=os.getenv("TERM", "vt220"),
        LANG="C.UTF-8",
    ) | env

    if env["PATH"] == "":
        del env["PATH"]

    try:
        return subprocess.run(
            cmdline,
            check=check,
            stdout=stdout,
            stderr=stderr,
            env=env,
            **kwargs,
            preexec_fn=foreground
        )
    except FileNotFoundError as e:
        print(f"{cmdline[0]} not found in PATH.", e)
        raise e
    except subprocess.CalledProcessError as e:
        raise e


def get_myip(version: int) -> IPAddress | None:
    tmpdir = Path("/var/tmp/ebox")
    if tmpdir.exists():
        from shutil import rmtree
        rmtree(tmpdir, ignore_errors=True)

    cmd = [
        "/home/pmn/src/n/libmnl/examples/rtnl/rtnl-addr-dump",
        "ebox",
        "/var/tmp/ebox"
    ]
    for addr_str in run(cmd, stdout=subprocess.PIPE, text=True).stdout.split():
        addr = ip_address(addr_str)
        if addr.version == version:
            return addr


def delete_record(args, rec: Record, api_config: apiConfig):
    endpoint = api_config.endpoint + '/dns/delete/' + args.root + '/' + str(rec.id)
    rec2del = rec.asdict
    print(f"delete:\n{pformat(rec2del)}")
    rec2del.update(
        {
            'apikey': api_config.apikey,
            'secretapikey': api_config.secretapikey,
        }
    )
    ret = json.loads(requests.post(endpoint, data=json.dumps(rec2del)).text)
    print(ret)


def update_record(root: str, rec: Record, api_config: apiConfig):
    endpoint = api_config.endpoint + f"/dns/editByNameType/{root}/{rec.type}/{rec.name}"
    rec2update = {
        'content': str(rec.content),
        'ttl': f"{rec.ttl}",
    }
    print(f"update:\n{pformat(rec2update)}")
    rec2update.update(
        {
            'apikey': api_config.apikey,
            'secretapikey': api_config.secretapikey,
        }
    )

    ret = json.loads(requests.post(endpoint, data=json.dumps(rec2update)).text)
    print(ret)


def set_record(args: argparse.Namespace, rec: Record, api_config: apiConfig):
    endpoint = api_config.endpoint + '/dns/create/' + args.root
    new_rec = rec.asdict
    print(f"set:\n{pformat(new_rec)}")
    new_rec.update(
        {
            'apikey': api_config.apikey,
            'secretapikey': api_config.secretapikey,
        }
    )

    ret = json.loads(requests.post(endpoint, data=json.dumps(new_rec)).text)
    print(ret)


# # at least the config and root domain is specified
# if len(sys.argv) > 2:
#     # load the config file into a variable
#     apiConfig = json.load(open(sys.argv[1]))
#     rootDomain = sys.argv[2].lower()

#     # check if a subdomain was specified as the third argument
#     if (len(sys.argv) > 3 and sys.argv[3] != '-i'):
#         subDomain = sys.argv[3].lower()
#         fqdn = subDomain + "." + rootDomain
#     else:
#         subDomain = ''
#         fqdn = rootDomain

#     # check if IP is manually specified.
#     # There's probably a more-elegant way to do this
#     if len(sys.argv) > 4 and sys.argv[3] == '-i':
#         myIP = sys.argv[4]
#     elif len(sys.argv) > 5 and sys.argv[4] == '-i':
#         myIP = sys.argv[5]
#     else:
#         # otherwise use the detected exterior IP address
#         myIP = getMyIP()

#     deleteRecord()
#     print(createRecord(ip_address(myIP).version)["status"])
# else:
#     print(
#         "Porkbun Dynamic DNS client, Python Edition\n\n"
#         "Error: not enough arguments. "
#         "Examples:\npython porkbun-ddns.py /path/to/config.json example.com\n"
#         "python porkbun-ddns.py /path/to/config.json example.com www\n"
#         "python porkbun-ddns.py /path/to/config.json example.com '*'\n"
#         "python porkbun-ddns.py /path/to/config.json example.com -i 10.0.0.1\n"
#     )

__prog__ = 'porkbun-ddns'


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=__prog__, description=__prog__,
                                     argument_default=argparse.SUPPRESS)
    parser.add_argument('-c', '--config', dest='cfg', type=Path,
                        default=Path(os.getcwd() + '/' + 'config.json'))
    parser.add_argument('root', type=str)
    parser.add_argument('type', type=RecordType, default=RecordType.AAAA)
    parser.add_argument('name', type=str)
    parser.add_argument('content', type=str, default="")
    parser.add_argument('--ttl', type=int, default=60)

    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = create_parser()
    args_parsed = parser.parse_args()

    return args_parsed


def main():
    args = parse_args()
    api_config: apiConfig
    with args.cfg.open("r") as f:
        api_config = apiConfig(**json.loads(f.read()))
    recs_raw = get_records(args, api_config)
    current_records: Set[Record] = set()
    for rec in recs_raw:
        current_records.add(Record(**rec))
    # for rec in current_records:
        # print(f"type={rec.type} name={rec.name} content={rec.content}")
        # print(f"{pformat(vars(rec))}")

    new_rec: Record | None = None
    if (args.type in (RecordType.A, RecordType.AAAA) and
            args.content == 'auto'):
        # content = get_myip(
        #     api_config,
        #     4 if args.type == RecordType.A else 6,
        # )
        # type = RecordType.A if content.version == 4 else RecordType.AAAA
        content = get_myip(4 if args.type == RecordType.A else 6)
        new_rec = Record(type=args.type, name=args.name, content=content,
                         ttl=args.ttl)
    else:
        new_rec = Record(type=args.type, name=args.name, content=args.content,
                         ttl=args.ttl)

    for rec in current_records:
        if rec.type == new_rec.type:
            if rec.name.split('.')[0] != new_rec.name:
                if new_rec.name in ('.', '') and rec.name == args.root:
                    delete_record(args, rec, api_config)
                    break
                else:
                    continue
            else:
                if (rec.content != new_rec.content or
                    rec.ttl != new_rec.ttl or
                    rec.prio != new_rec.prio or
                        rec.notes != new_rec.notes):
                    new_rec.id = rec.id
                    update_record(args.root, new_rec, api_config)
                return

    set_record(args, new_rec, api_config)
    return


if __name__ == '__main__':
    main()
