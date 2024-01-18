#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path

from graphviz import Source

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("dot_file", type=Path)
    args = parser.parse_args()
    dot = args.dot_file.read_text()
    s = Source(dot, filename="graph.dot", format="pdf")
    s.view(cleanup=True)
