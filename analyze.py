"""Decrypts traffic generated by ic2kp (rekobee).

Created for the HTB challenge (https://app.hackthebox.com/challenges/295). There
you can find the ic2kp client and a sample capture.
"""

__help__ = """common problems:

pyshark.tshark.tshark.TSharkNotFoundException : TShark not found
    Change wireshark (tshark & dumpcap) location in 'config.ini'

verbose levels:

1) -v: extra information;
2) -vv: packets and advances.

example: analyze.py -c capture.pcap -s S3cr3tP@ss -vv
"""

import argparse
import pyshark

import core
import core.utils


def get_args():
    parser = argparse.ArgumentParser(
        description = __doc__,
        epilog = __help__,
        formatter_class = argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-c",
        default = "capture.pcap",
        dest = "capture",
        help = "path to capture file from wireshark",
        metavar = "CAPTURE",
        type = pyshark.FileCapture
    )
    parser.add_argument(
        "-s",
        default = "S3cr3tP@ss",
        dest = "secret",
        help = "ic2kp session shared secret",
        metavar = "SECRET",
        type = str
    )
    parser.add_argument(
        "-o",
        default = "output.txt",
        dest = "output",
        help = "output file path (default: output.txt)",
        metavar = "OUTPUT",
        type = str
    )
    parser.add_argument(
        "-i",
        default = None,
        dest = "initial",
        help = "initial packet index",
        metavar = "INDEX",
        type = int
    )
    parser.add_argument(
        "-v",
        action = "count",
        default = 0,
        dest = "verbose",
        help = "everything in detail",
    )
    parser.add_argument(
        "--signature",
        default = "5890ae86f1b91cf6298395711dde580d",
        dest = "signature",
        help = "ic2kp magic hex signature, e.g. 5890...580d",
        metavar = "HEX",
        type = str
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    try:
        core.analyze(**vars(args))
    except Exception as exception:
        core.utils.error(str(exception))
        if args.verbose != 0:
            raise