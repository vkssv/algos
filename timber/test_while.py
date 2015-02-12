#! /usr/bin/python2.7
# -*- coding: utf-8 -*-
__author__ = 'root'

import sys, os, importlib, logging, re, binascii, math, zlib, unicodedata

from email import iterators
from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple



def _get_lang_(msg):

    charset_map = {'x-sjis': 'shift_jis'}
    # partial support of asian encodings, just to decode in UTF without exceptions
    # and normilize with NFC form: one unicode ch per symbol
    langs_map = {
                    'ru'    :  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                    'fr'    :  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252'],
                    'jis'   :  ['shift_jis']
    }

    for p in iterators.typed_subpart_iterator(msg):
        decoded_line = p.get_payload(decode=True)

        # determine charset:
        charset = 'utf-8'
        for ch in (p.get_content_charset(), p.get_charset()):
            if ch and ch.lower() != 'utf-8':
                if ch in charset_map.keys():
                    charset =  charset_map.get(ch)
                    break
                else:
                    charset = ch

        # Python2.7 => try to decode all lines from their particular charsets to unicode,
        # add U+FFFD, 'REPLACEMENT CHARACTER' if faces with UnicodeDecodeError
        decoded_line = decoded_line.decode(charset, 'replace')
        if not decoded_line.strip():
            continue
        type(decoded_line)
        decoded_line = unicodedata.normalize('NFC', decoded_line)

        # determine lang:
        # from charset attribute in Content-Type
        lang = 'en'
        for l in langs_map.iterkeys():
            if filter(lambda ch: re.match(ch, charset, re.I), langs_map.get(l)):
                lang = l
                yield(decoded_line, p.get_content_type(), lang)

        # from r'(Content|Accept)-Language' headers
        l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0),msg.items()))[-1:]
        if l:
            lang = ''.join(msg.get(''.join(l)).split('-')[:1])

        yield(decoded_line, p.get_content_type(), lang)

