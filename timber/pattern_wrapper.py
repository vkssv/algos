import sys, os, importlib, logging
from email import iterators, base64mime, quoprimime
from bs4 import BeautifulSoup
from collections import OrderedDict

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class BasePattern(object):
    """Base parent class for created all other pattern classes.
    Provides access to some pre-parsed attributes of msg"""
    INIT_SCORE = 0
    MIN_TOKEN_LEN = 3

    def __init__(self, msg):
        self.msg = msg
        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received')])
        logger.debug(self.parsed_rcvds)

    def get_text_parts(self):
        self.text_parts = []
        encodings = {
                            'quoted-printable'  : lambda payload: quoprimime.body_decode(payload),
                            'base64'            : lambda payload: base64mime.body_decode(payload)
                        }

        decoded_line = ''
        parts_iterator = iterators.typed_subpart_iterator(self.msg)
        while(True):
            try:
                part = next(parts_iterator)
            except StopIteration as err:
                break

            if part:
                decoded_line = part.get_payload()
                if part.get('Content-Transfer-Encoding') in encodings.keys():
                    f = encodings.get(part.get('Content-Transfer-Encoding'))
                    decoded_line = f(decoded_line)
                    lines = decoded_line.split('\r\n')

                self.text_parts.append((lines, part.get_content_charset(), part.get_content_type()))

        return (self.text_parts)

    def get_rcvds(self, rcvds_num=0):

        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received')])[-1*rcvds_num:]
        return (self.parsed_rcvds)

    def get_mime_struct(self):

        self.mime_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition']

        self.mime_parts= OrderedDict()

        for part in self.msg.walk():
            all_heads = [name.lower() for name in part.keys()]
            #print(all_heads)

            part_dict = {}
            part_key = 'text/plain'
            for head in filter(lambda n: all_heads.count(n), mime_heads):
                part_dict[head] = part.get_all(head)
                if head == 'content-type':
                    part_key = part.get_all(head)

            if len(part_dict) == 0:
                continue

            self.mime_parts[part_key] = part_dict

        return(self.mime_parts)

    def get_mime_structure_crc(self):
        mime_parts = self.get_mime_struct()
        all_content_types = tuple(reduce(add,[dict.get('content-type') for dict in mime_parts]))
        line = ''.join([l.partition(';')[0] for l in all_content_types])

        return(binascii.crc32(line))

    def get_nest_level(self):
        all_content_types = reduce(add,[dict.get('content-type') for dict in self.mime_parts])
        all_content_types = [x.partition(';')[0] for x in all_content_types]
        self.level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),all_content_types))

        return(self.level)

    def get_url_list(self):
        text_parts = self.get_text_parts()

        self.url_list = []
        url_regexp= ur'(https?|mailto|ftps?):'
        for obj in text_parts:
            lines_list, encoding, content_type = obj
            if encoding:
                    obj = obj.decode(encoding)

            if 'html' in content_type:
                soup = BeautifulSoup(obj)
                self.url_list.extend(soup)

            else:

                lines = obj.split('\r\n')
                self.url_list.extend(filter(lambda url: re.search(ur'(https?|mailto|ftps?):',url),[l.strip() for l in lines]))

        return(self.url_list)























class PatternFactory(object):
    """Factory for creating on the fly set of rules for desired class"""

    def New(self, msg, label):
        #print(label)
        try:

            pattern = importlib.import_module(label + '_pattern')
            # logger.debug ((check.title()).replace('_',''))
            current_test_obj = getattr(pattern, (label.title() + 'Pattern'))

        except Exception as details:
            raise

        return (current_test_obj(msg))

MetaPattern = PatternFactory()
