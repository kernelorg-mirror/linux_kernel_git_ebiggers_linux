#!/usr/bin/python

import argparse
import sys

all_ciphers = [
    {
        'name': 'aes',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', 'aesni', 'ce', 'neonbs', 'neon'],
    }, {
        'name': 'blowfish',
        'blocksize': 8,
        'keysizes': [4, 16, 24, 32, 56],
        'impls': ['generic', 'asm'],
    }, {
        'name': 'camellia',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', 'asm', 'aesni', 'aesni-avx'],
    }, {
        'name': 'cast5',
        'blocksize': 8,
        'keysizes': [5, 12, 16],
        'impls': ['generic', 'avx'],
    }, {
        'name': 'cast6',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', 'avx'],
    }, {
        'name': 'des3_ede',
        'blocksize': 8,
        'keysizes': [24],
        'impls': ['generic', 'asm']
    }, {
        'name': 'lea',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', 'neon'],
    }, {
        'name': 'serpent',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', 'sse2', 'avx', 'avx2'],
    }, {
        'name': 'twofish',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', '3way', 'avx'],
    }, {
        'name': 'speck128',
        'blocksize': 16,
        'keysizes': [16, 24, 32],
        'impls': ['generic', 'neon'],
    }, {
        'name': 'speck64',
        'blocksize': 8,
        'keysizes': [12, 16],
        'impls': ['generic', 'neon'],
    }, {
        'name': 'salsa20',
        'blocksize': 1,
        'keysizes': [32],
        'impls': ['generic', 'asm'],
    }, {
        'name': 'chacha20',
        'blocksize': 1,
        'keysizes': [32],
        'impls': ['generic', 'simd'],
    }, {
        'name': 'hpolyc(xchacha20,aes)',
        'blocksize': 1,
        'keysizes': [32],
        'impls': [],
    }, {
        'name': 'hpolyc(xchacha12,aes)',
        'blocksize': 1,
        'keysizes': [32],
        'impls': [],
    }
]

all_ciphers_by_name = {cipher['name']: cipher for cipher in all_ciphers}

def MB_per_s(nbytes, ns_elapsed):
    return (nbytes * 1000) / ns_elapsed

def benchmark_skcipher(algname, friendly_name, keysize, args):
    enc_time = (1 << 64)
    dec_time = (1 << 64)
    prev_measurement = None

    for _try in range(int(args.ntries)):
        with open('/proc/cryptobench', 'rt+') as f:
            optstring = ''
            optstring += ' algtype=skcipher'
            optstring += ' algname=' + algname
            optstring += ' keysize=' + str(keysize)
            optstring += ' niter=' + str(args.niter)
            optstring += ' bufsize=' + str(args.bufsize)
            if args.inplace:
                optstring += ' inplace'
            if args.sgl_fuzz:
                optstring += ' sgl_fuzz'
            f.write(optstring + '\n')
            f.seek(0)
            resline = f.readline().split()

        if resline[0] == 'ERROR':
            if resline[1] == 'ALG_NOT_FOUND':
                return
            print('{} {}'.format(algname, resline[1]))
            return
        resitems = {}
        for item in resline[1:]:
            (key, value) = item.split('=')
            resitems[key] = value

        driver_name = resitems['driver_name']
        measurement = resitems['measurement']
        if prev_measurement is not None and measurement != prev_measurement:
            sys.stderr.write('Algorithm {} (driver: {}) gave inconsistent results!'.format(algname, driver_name))
            sys.exit(1)
        prev_measurement = measurement
        enc_time = min(enc_time, int(resitems['enc_time']))
        dec_time = min(dec_time, int(resitems['dec_time']))

    print('{:17} {:30} {:30} {:4.1f} {:4.1f} {:17}'.format(
                friendly_name,
                algname,
                driver_name,
                MB_per_s(int(args.niter) * int(args.bufsize), enc_time),
                MB_per_s(int(args.niter) * int(args.bufsize), dec_time),
                measurement))

def keysize_for_mode(mode, keysize, blocksize):
    if mode == 'xts':
        return keysize * 2
    if mode == 'lrw':
        return keysize + blocksize
    return keysize

def benchmark_cipher_spec(cipher, keysize, args):
    blocksize = cipher['blocksize']
    name = cipher['name']
    if blocksize == 1:
        benchmark_skcipher(name, name, keysize, args)
        if args.all_impls:
            for impl in cipher['impls']:
                benchmark_skcipher('{}-{}'.format(name, impl), name, keysize, args)
        return

    available_modes = ['ecb', 'cbc', 'ctr']
    if blocksize == 16:
        available_modes.extend(['lrw', 'xts'])

    for mode in available_modes if args.modes is None else args.modes:
        algname = '{}({})'.format(mode, name)
        friendly_name = '{}-{}-{}'.format(name.upper(), keysize*8, mode.upper())
        actual_keysize = keysize_for_mode(mode, keysize, blocksize)
        benchmark_skcipher(algname, friendly_name, actual_keysize, args)

    if args.all_impls:
        for impl in cipher['impls']:
            for mode in available_modes if args.modes is None else args.modes:
                if impl == 'generic':
                    if mode == 'xts' or mode == 'lrw':
                        algname = '{}(ecb({}-generic))'.format(mode, name)
                    else:
                        algname = '{}({}-generic)'.format(mode, name)
                else:
                    algname = '{}-{}-{}'.format(mode, name, impl)
                friendly_name = '{}-{}-{}'.format(name.upper(), keysize*8, mode.upper())
                actual_keysize = keysize_for_mode(mode, keysize, blocksize)
                benchmark_skcipher(algname, friendly_name, actual_keysize, args)

parser = argparse.ArgumentParser(description='Run cryptographic benchmarks.')

parser.add_argument('--ciphers', action='store', help='ciphers to enable')
parser.add_argument('--modes', action='store', help='modes to enable')
parser.add_argument('--keysizes', action='store', help='keysizes to enable')
parser.add_argument('--all-impls', action='store_true', help='test all impls')
parser.add_argument('--ntries', action='store', default=1, help='num tries per benchmark')
parser.add_argument('--bufsize', action='store', default=4096, help='buffer size')
parser.add_argument('--niter', action='store', default=4096, help='num iterations per benchmark')
parser.add_argument('--inplace', action='store_true', default=False, help='crypt in place?')
parser.add_argument('--sgl-fuzz', action='store_true', default=False, help='use random sglists')

args = parser.parse_args()

if args.ciphers is not None:
    cipher = ''
    nest = 0
    ciphers = set()
    for c in args.ciphers + ',':
        if c == '(':
            nest += 1
        elif c == ')':
            nest -= 1
        elif c == ',' and nest == 0 and cipher != '':
            ciphers.add(cipher)
            cipher = ''
            continue
        cipher += c
    args.ciphers = ciphers

if args.modes is not None:
    args.modes = set(x for x in args.modes.split(','))

if args.keysizes is not None:
    args.keysizes = set(int(x) for x in args.keysizes.split(','))

if args.ciphers is None:
    ciphers = all_ciphers
else:
    ciphers = [all_ciphers_by_name[x] for x in args.ciphers]
ciphers = sorted(ciphers, key = lambda x: x['name'])

for cipher in ciphers:
    if args.keysizes is None:
        keysizes = cipher['keysizes']
    else:
        keysizes = args.keysizes
    keysizes = sorted(keysizes)
    for keysize in keysizes:
        benchmark_cipher_spec(cipher, keysize, args)
