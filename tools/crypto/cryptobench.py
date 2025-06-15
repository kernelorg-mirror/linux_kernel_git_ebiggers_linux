#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Crypto algorithm benchmark and testing script
#
# Userspace utility for /proc/cryptobench (CONFIG_CRYPTO_BENCHMARK).
#
# Copyright 2018 Google LLC
#

import argparse
import subprocess
import sys

def error(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)

def megabytes_per_sec(args, ns_elapsed):
    nbytes = int(args.niter) * int(args.datasize)
    return (nbytes * 1000) / ns_elapsed

class BenchmarkError(Exception):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type

def proc_cryptobench(cmd, args):
    if args.adb:
        sh_cmd = ''
        if args.cpu_mask:
            sh_cmd += ' taskset ' + args.cpu_mask
        sh_cmd += f' sh -c "echo -e \'{cmd}\' > /proc/cryptobench; cat /proc/cryptobench"'
        return str(subprocess.check_output(['adb', 'shell', sh_cmd]), 'utf-8')
    if args.cpu_mask:
        raise ValueError('TODO: support --cpu-mask without --adb')
    with open('/proc/cryptobench', 'rt+', encoding='ascii') as file:
        file.write(cmd)
        file.seek(0)
        return file.readline()

def do_kernel_benchmark(algname, algtype, keysize, args):
    cmd = ''
    cmd += ' aadsize=' + str(args.aadsize)
    cmd += ' algname=' + algname
    cmd += ' algtype=' + algtype
    cmd += ' datasize=' + str(args.datasize)
    if args.force_ahash:
        cmd += ' force_ahash'
    if args.inplace:
        cmd += ' inplace'
    cmd += ' keysize=' + str(keysize)
    cmd += ' niter=' + str(args.niter)
    cmd += '\n'

    fields = proc_cryptobench(cmd, args).split()
    if fields[0] == 'ERROR':
        raise BenchmarkError('error with algorithm ' + algname, fields[1])

    results = {}
    for item in fields[1:]:
        (key, value) = item.split('=')
        results[key] = value
    return results

def check_measurement(prev_measurement, results, algname):
    measurement = results['measurement']
    if prev_measurement is not None and measurement != prev_measurement:
        error('Algorithm {} (driver: {}) gave inconsistent results!'.format(
              algname, results['driver_name']))
    return measurement

def do_benchmark(algname, algtype, keysize, args):
    time = 2**64
    enc_time = 2**64
    dec_time = 2**64
    measurement = None
    for _try in range(args.ntries):
        try:
            results = do_kernel_benchmark(algname, algtype, keysize, args)
        except BenchmarkError as ex:
            print(f'{algname} {ex.error_type}')
            return
        measurement = check_measurement(measurement, results, algname)
        if algtype == 'hash':
            time = min(time, int(results['time']))
        else:
            enc_time = min(enc_time, int(results['enc_time']))
            dec_time = min(dec_time, int(results['dec_time']))
    if algtype == 'hash':
        print('{:30} {:6.0f}'.format(
              results['driver_name'],
              round(megabytes_per_sec(args, time))))
    else:
        print('{:30} {:6.0f} {:6.0f}'.format(
              results['driver_name'],
              round(megabytes_per_sec(args, enc_time)),
              round(megabytes_per_sec(args, dec_time))))

def parse_algnames(optarg):
    cur_name = ''
    nesting_level = 0
    names = []
    for char in optarg + ',':
        if char == '(':
            nesting_level += 1
        elif char == ')':
            nesting_level -= 1
            if nesting_level < 0:
                raise ValueError('Malformed argument: ' + optarg)
        elif char == ',' and nesting_level == 0 and cur_name != '':
            names.append(cur_name)
            cur_name = ''
            continue
        cur_name += char
    return names

def main():
    parser = argparse.ArgumentParser(description='Run cryptographic benchmarks.')

    parser.add_argument('--aadsize', action='store', default=32,
                        help='AAD size to use, in bytes')
    parser.add_argument('--adb', action='store_true', default=False,
                        help='use connected Android device')
    parser.add_argument('--aeads', action='store',
                        help='list of aead algorithms to benchmark')
    parser.add_argument('--datasize', action='store', default=4096,
                        help='data size to use, in bytes')
    parser.add_argument('--cpu-mask', action='store',
                        help='CPUs to allow (default: all)')
    parser.add_argument('--force-ahash', action='store_true', default=False,
                        help='use ahash even if shash is available?')
    parser.add_argument('--hashes', action='store',
                        help='list of hash algorithms to benchmark')
    parser.add_argument('--inplace', action='store_true', default=False,
                        help='crypt in place?')
    parser.add_argument('--keysizes', action='store',
                        help='list of key sizes to use, in bytes')
    parser.add_argument('--niter', action='store', default=4096,
                        help='num iterations per benchmark')
    parser.add_argument('--ntries', action='store', type=int, default=100,
                        help='num tries per benchmark')
    parser.add_argument('--skciphers', action='store',
                        help='list of skcipher algorithms to benchmark')

    args = parser.parse_args()

    if args.aeads:
        args.aeads = parse_algnames(args.aeads)

    if args.hashes:
        args.hashes = parse_algnames(args.hashes)

    if args.skciphers:
        args.skciphers = parse_algnames(args.skciphers)

    if args.ntries <= 0:
        error('Must have ntries >= 1')

    if not (args.aeads or args.hashes or args.skciphers):
        error('Must specify at least one of --aeads, --hashes, or --skciphers')

    if args.keysizes:
        args.keysizes = [int(x) for x in args.keysizes.split(',')]

    if args.aeads:
        if not args.keysizes:
            error('--keysizes must be specified')
        for algname in args.aeads:
            for keysize in args.keysizes:
                do_benchmark(algname, 'aead', keysize, args)

    if args.hashes:
        args.hashes = sorted(args.hashes)
        for algname in args.hashes:
            for keysize in args.keysizes if args.keysizes else [0]:
                do_benchmark(algname, 'hash', keysize, args)

    if args.skciphers:
        if not args.keysizes:
            error('--keysizes must be specified')
        for algname in args.skciphers:
            for keysize in args.keysizes:
                do_benchmark(algname, 'skcipher', keysize, args)

main()
