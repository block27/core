# usage: drunken_bishop.py [-h] [--mode {md5,sha256}] fingerprint
#
# Generate randomart from fingerprint
#
# positional arguments:
#   fingerprint
#
# optional arguments:
#   -h, --help            show this help message and exit
#   --mode {md5,sha256}, -m {md5,sha256}

import argparse
import base64
import numpy as np
import random
import sys

from random import randrange


def get_steps(bits):
    bits_grouped = np.array(bits, dtype=np.int8).reshape((-1, 4, 2))
    bits_grouped_reordered = np.flip(bits_grouped, axis=1)
    return bits_grouped_reordered.reshape((-1, 2))


def drunken_bishop(steps):
    positions = np.zeros((9, 17), dtype=np.int8)

    current_position = np.array([4, 8])


    def move(b0, b1):
        if (b0, b1) == (0, 0):
            return (-1, -1)
        elif (b0, b1) == (0, 1):
            return (-1, 1)
        elif (b0, b1) == (1, 0):
            return (1, -1)
        elif (b0, b1) == (1, 1):
            return (1, 1)
        raise Exception('Impossible move: ({}, {})'.format(b0, b1))


    for step in steps:
        positions[tuple(current_position)] += 1
        current_position += move(step[0], step[1])
        if current_position[0] >= positions.shape[0]:
            current_position[0] = positions.shape[0] - 1
        elif current_position[0] <= 0:
            current_position[0] = 0
        if current_position[1] >= positions.shape[1]:
            current_position[1] = positions.shape[1] - 1
        elif current_position[1] <= 0:
            current_position[1] = 0

    positions[(4, 8)] = 15
    positions[tuple(current_position)] = 16
    return positions


def print_randomart(atrium, mode):
    lowV = [31, 32, 33, 34, 35, 36]
    random.shuffle(lowV)

    midV = [91, 92, 93, 94, 95, 96]
    random.shuffle(midV)

    higV = [33, 34, 35]
    random.shuffle(higV)

    values = {
        0: ' ',
        1: '\033[{0}m.\033[0m'.format(lowV.pop()),
        2: '\033[{0}mo\033[0m'.format(lowV.pop()),
        3: '\033[{0}m+\033[0m'.format(lowV.pop()),
        4: '\033[{0}m=\033[0m'.format(lowV.pop()),
        5: '\033[{0}m*\033[0m'.format(lowV.pop()),
        6: '\033[{0}mB\033[0m'.format(lowV.pop()),
        7: '\033[{0}mO\033[0m'.format(midV.pop()),
        8: '\033[{0}mX\033[0m'.format(midV.pop()),
        9: '\033[{0}m@\033[0m'.format(midV.pop()),
        10: '\033[{0}m%\033[0m'.format(midV.pop()),
        11: '\033[{0}m&\033[0m'.format(midV.pop()),
        12: '\033[{0}m#\033[0m'.format(midV.pop()),
        13: '\033[37m/\033[0m',
        14: '\u001b[{0};1m^\u001b[0m'.format(higV.pop()),
        15: '\u001b[{0};1mS\u001b[0m'.format(higV.pop()),
        16: '\u001b[{0};1mE\u001b[0m'.format(higV.pop()),
    }

    print(f'+---[  {mode}   ]----+')
    for r in atrium:
        print('|', end='')
        for c in r:
            print(values[c], end='')
        print('|')
    print('+-----------------+')


def get_md5_bits(fingerprint):
    return np.array([list('{:08b}'.format(int(i, 16))) for i in fingerprint.split(':')])


def get_sha256_bits(fingerprint):
    missing_padding = 4 - (len(fingerprint) % 4)
    fingerprint += '=' * missing_padding
    return np.array([list('{:08b}'.format(i)) for i in base64.b64decode(fingerprint)])


def main():
    parser = argparse.ArgumentParser(
        description='Generate randomart from fingerprint')
    parser.add_argument('--mode', '-m', choices=['md5', 'sha256'], default='md5')
    parser.add_argument('fingerprint', type=str)
    args = parser.parse_args()

    bits = None;
    if args.mode == 'md5':
        bits = get_md5_bits(args.fingerprint)
    elif args.mode == 'sha256':
        bits = get_sha256_bits(args.fingerprint)
    else:
        raise Exception('Unsupported hashing mode: {}'.format(args.mode))

    steps = get_steps(bits)
    atrium = drunken_bishop(steps)


    print_randomart(atrium, args.mode[:3].upper())


if __name__ == '__main__':
    main()
