#! /usr/bin/env python3

import sys, os, logging, re, email, argparse, time, math
from email.parser import BytesParser
from email.header import decode_header
from email import iterators, base64mime, quoprimime
from bs4 import BeautifulSoup
from collections import OrderedDict, defaultdict, Counter
from itertools import repeat


# define needed functions
def cut_header_from_body(email):
    doc = open(email, "rb")
    doc_content = ''.join(doc.readlines())
    doc.close()
    # cut headers from body
    headers_str = re.split('\r\n\r\n', doc_content)[0]
    corp_lines = re.split('\r\n\r\n', doc_content)[1:]

    # normilize lines in body
    b_list = sum([b.split('\r\n') for b in corp_lines], [])
    corp_lines_list = [l.strip() for l in b_list]
    corp_lines_list = filter(lambda x: len(x) != 0, corp_lines_list)

    return (headers_str, corp_lines_list)

def quote_the_value(value):
    return ('"'+str(value)+'"')

def headers_parser(head_string, email):
    d = os.path.basename(email)
    headers_dict = {}
    cur_header = None

    for h in head_string.split('\r\n'):
        # h = h.rstrip()
        # match the start of header
        if re.match(r'^[\S]+:.*$', h):
            header_name, value = h.split(':', 1)
            headers_dict[header_name] = value
            cur_header = header_name
        # match the start of folded value of the header
        elif re.match(r'^(\t|\x20)+.*$', h):
            headers_dict[cur_header] = headers_dict.get(cur_header)+' '+h
        else:
            # just skip unmached headers
            continue

    for h_key in headers_dict.iterkeys():
        logger.debug('__HEADER__( '+(d)+' ):\t'+h_key+' --> '+quote_the_value(headers_dict.get(h_key)))

    return (headers_dict)

def get_mime_info(msg,d_name):

    print(email.iterators._structure(msg))
    logger.debug('\n')
    mime_heads = ['content-type','content-transfer-encoding','content-id','content-disposition']
    total =0
    for part in  msg.walk():

        all_heads = [name.lower() for name in part.keys()]
        for head in filter(lambda n: all_heads.count(n), mime_heads):
            logger.debug(d_name+':'+head.upper()+' --> '+str(part.get_all(head)))

        total += all_heads.count('content-type')

    logger.debug('\n')
    logger.debug('PAYLOAD( '+(d_name)+' ): ==> '+str(len(msg.get_payload())))
    logger.debug('MIME_PARTS_NUM( '+(d_name)+' ): ==> '+str(total))

    return

def replace(x):
    if x is None:
        x=''

    return(x)

def get_text_parts(msg):

    text_parts = []
    decoded_line = ''
    parts_iterator = iterators.typed_subpart_iterator(msg)
    while(True):
        try:
            part = next(parts_iterator)

        except StopIteration as err:
            break

        if part:

            decoded_line = part.get_payload(decode=True)

            charset_map = {'x-sjis': 'shift_jis'}

            charset = ''
            for charset in (part.get_content_charset(), part.get_charset()):
                if charset:
                    logger.debug('........'+charset.upper())
                    if charset in charset_map.keys():
                        charset =  charset_map.get(charset)

            if isinstance(decoded_line, bytes) and charset:
                logger.debug('........'+charset.upper())
                decoded_line = decoded_line.decode(charset)


            elif isinstance(decoded_line, bytes):
                decoded_line = decoded_line.decode('utf-8', 'replace')

            logger.debug('........'+decoded_line+'...................')
            text_parts.append((decoded_line, part.get_content_charset(), part.get_content_type()))

    return (text_parts)

def get_mime_struct(msg):

    mime_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition']
    mime_parts= OrderedDict()

    for part in msg.walk():
        all_heads = [name.lower() for name in part.keys()]

        part_dict = {}
        part_key = 'text/plain'
        for head in filter(lambda n: all_heads.count(n), mime_heads):

            if head == 'content-type':

                part_key = part.get(head)
                part_key = str(part_key).partition(';')[0].strip()
                part_dict[head] = re.sub(part_key+';','',str(part.get(head)),re.I)

            else:
                part_dict[head] = part.get(head)

        mime_parts[(part_key.partition(';')[0]).strip()] = part_dict

    return(mime_parts)

def get_nest_level(msg):

    mime_parts = get_mime_struct(msg)
    level = len(list(filter(lambda n: re.match('(multipart|message)',n,re.I), list(mime_parts.keys()))))

    return(level)

def get_url_list(msg, d_name, tags_list):

    text_parts = get_text_parts(msg)
    url_list = []
    tags_stat = defaultdict(list)
    url_regexp= r'(((https?|ftps?):\/\/)|www:).*'
    for line, encoding, content_type in text_parts:

        if 'html' in content_type:
            soup = BeautifulSoup(line)
            if soup.a:
                url_list.extend(soup.a)

            # ugly code just for searching regularities
            logger.debug('===================HTML BODY PART====================')

            object_list=list()
            for tag in tags_list:
                object_list = soup.find_all(tag)

                if object_list:
                    tags_stat[tag].append(len(object_list))
                    logger.debug(tag.upper()+" ( "+d_name+" ) : tag count: "+str(len(object_list)))
                    logger.debug("All "+tag.upper()+" attributes: ")
                    for obj in object_list:
                        logger.debug('\t'+str(obj.attrs))




                else:
                    logger.debug(tag.upper()+" ( "+d_name+" ) NONE ")

        else:

            x = list(filter(lambda y: y, [l.strip() for l in line.split()]))

            if x:
                url_list.extend(list(filter(lambda url: re.search(url_regexp, url, re.I), x)))

    #logger.debug('URL LIST >>>> '+str(url_list))
    return(url_list, tags_stat)


if __name__ == "__main__":
    usage = "usage: %prog [ training_directory | file ] -b"
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument("PATH", type=str, help="path to collection dir or to email")
    parser.add_argument("-b", action = "store_true", default=False, help="show only bodies MIME structures and content")
    parser.add_argument("-stat", action = "store_true", default=False, help="print headers, tags, urls stat")
    args = parser.parse_args()

    tmp = '/tmp'
    formatter = logging.Formatter('%(message)s')
    logger = logging.getLogger()

    logger.setLevel(logging.INFO)
    if args.stat:
        logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler(os.path.join(tmp, 'headers_'+os.path.basename(args.PATH)+'_'+time.strftime("%y%m%d_%H%M", time.localtime())+'.log'), mode = 'w')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    # 1. create train dataset
    try:
        parser = BytesParser()
        pathes = []
        if os.path.isfile(args.PATH):
            pathes = [args.PATH]
        elif os.path.isdir(args.PATH):
            for path, subdirs, docs in os.walk(args.PATH):
                for d in docs:
                    pathes.append(os.path.join(path, d))

        common_heads_list = []
        header_counts_list = []
        urls_count_list = []
        urls_lens = []

        for sample_path in pathes:
            with open(sample_path, 'rb') as f:
                msg = parser.parse(f)

            logger.info('\nPATH: '+sample_path.upper()+'\n')

            filename = os.path.basename(sample_path)
            if not args.b:

                #logger.debug('\n============== common garden parser ====================\n')
                #headers_parser(cut_header_from_body(sample_path)[0], sample_path)

                logger.info('\n============== parser from STL email ====================\n')
                for k in msg.keys():
                    if k == 'Subject':

                        subj_parts_list = [(l[0],(replace(l[1])).upper()) for l in decode_header(msg.get(k))]
                        logger.info('HEADER( '+(filename)+' ):\t'+k+' ==> '+quote_the_value(subj_parts_list))

                    else:
                        logger.info('HEADER( '+(filename)+' ):\t'+k+' ==> '+quote_the_value(str(msg.get(k))))


            tags_list = ['table', 'tr', 'td', 'img', 'p', 'lu','li','div','span','style','script','a']
            d = [ [] for i in repeat(None, len(tags_list)) ]
            tags = Counter(dict(zip(tags_list,d)))
            i = 0
            url_list, tags_dict = get_url_list(msg, filename, tags_list)

            logger.debug('==========URL_LIST==========')
            logger.debug('>> URL LIST '+str(url_list))
            logger.debug('\n')

            if tags_dict:
                tags_dict = dict(tags_dict.items())
                logger.debug('>> CURRENT TAGS COUNTS '+str(tags_dict))
                tags.update(tags_dict)

            for l in url_list:
                logger.debug('\t'+str(i)+'. >'+str(l)+'<')
                i +=1
                urls_lens.append(len(l))

            logger.debug('URL LIST LEN: '+str(len(url_list)))
            urls_count_list.append(len(url_list))


            logger.info('NEST LEVEL: '+str(get_nest_level(msg)))

            header_counts_list.append(len(msg.keys()))

            heads_list = msg.keys()
            common_heads_list.extend([(name, heads_list.count(name)) for name in heads_list])


            logger.info('PREAMBLE ( '+(filename)+' ): ==> '+quote_the_value(str(msg.preamble)))
            logger.info('STRUCTURE')
            logger.info('\t'+str(email.iterators._structure(msg)))
            logger.info("IS_MULTIPART_FLAG = "+str(msg.is_multipart()))
            if msg.is_multipart():

                d = get_mime_struct(msg)
                logger.info('=====================================')
                for k in d.keys():
                    logger.info('\t{0:25} {1:}'.format(k,str(d.get(k))))

                logger.info('=====================================')

            logger.info('EPILOGUE ( '+(filename)+' ): ==> '+quote_the_value(str(msg.epilogue)))


            logger.info('========== BODIES PARTS ==========\n')
            bodies_parts = get_text_parts(msg)
            n = 0
            pairs=tuple()
            for mime_text_part, encoding, content_type in bodies_parts:

                if 'html' in content_type:
                    soup = BeautifulSoup(mime_text_part)
                    if soup.body and soup.body.stripped_strings:
                        pairs = enumerate(soup.body.stripped_strings)

                elif mime_text_part:
                    pairs = enumerate(mime_text_part.split('\n'))

                if pairs:
                    for num, s in pairs:
                        logger.debug(str(num)+': '+s)

                    logger.info('==========================================================')


        if args.stat:
            logger.debug('\n============== HEADS STAT ====================\n')
            heads = [ i[0] for i in common_heads_list ]
            unique = tuple(set([ i[0] for i in common_heads_list ]))
            unique_list = list(zip(tuple([heads.count(u) for u in unique]),unique))

            unique_list.sort()

            for item in unique_list:
                value,key = item
                logger.debug(key+' --> '+str(value))

            logger.debug('================ TAGS and URLS STAT ================= ')
            logger.debug('AVG URL LIST LEN: '+str(float(sum(urls_count_list))/float(len(urls_count_list))))
            logger.debug('AVG URL LEN: '+str(float(sum(urls_lens))/float(len(urls_lens))))
            logger.debug('AVG HEADS COUNT: '+str(float(sum(header_counts_list))/float(len(header_counts_list))))


            for t in tags.keys():
                appears = len(tags.get(t))
                if appears == 0:
                    appears = 1 # :-)
            total_count = sum(tags.get(t))
            logger.debug('AVG '+t.upper()+' count '+str(math.ceil(float(total_count/appears))))


    except Exception as details:
        logger.error(str(details))
        raise




