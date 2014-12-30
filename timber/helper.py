#! /usr/bin/env python3

import sys, os, logging, re, email, argparse, time
from email.parser import BytesParser
from email.header import decode_header
from email import iterators, base64mime, quoprimime
from bs4 import BeautifulSoup
from collections import OrderedDict


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
    print
    mime_heads = ['content-type','content-transfer-encoding','content-id','content-disposition']
    total =0
    for part in  msg.walk():

        all_heads = [name.lower() for name in part.keys()]
        for head in filter(lambda n: all_heads.count(n), mime_heads):
            logger.debug(d_name+':'+head.upper()+' --> '+str(part.get_all(head)))

        total += all_heads.count('content-type')

    print
    logger.debug('PAYLOAD( '+(d_name)+' ): ==> '+str(len(msg.get_payload())))
    logger.debug('MIME_PARTS_NUM( '+(d_name)+' ): ==> '+str(total))

    return

def replace(x):
    if x is None:
        x=''

    return(x)

def replace(x):
    if x is None:
        x=''

    return(x)

def get_text_parts(msg):

    text_parts = []
    encodings = {
                            'quoted-printable'  : lambda payload: quoprimime.body_decode(payload),
                            'base64'            : lambda payload: base64mime.body_decode(payload)
                }

    decoded_line = ''
    parts_iterator = iterators.typed_subpart_iterator(msg)
    while(True):
        try:
            part = next(parts_iterator)
                #logger.debug("next text part: "+str(part))
        except StopIteration as err:
            break

        if part:
            decoded_line = part.get_payload()
                #logger.debug("decoded_line "+str(decoded_line))
                #logger.debug("part.keys() "+str(part.keys()))

            if part.get('Content-Transfer-Encoding') in encodings.keys():
                f = encodings.get(part.get('Content-Transfer-Encoding'))
                decoded_line = f(decoded_line)

            #print(type(decoded_line))

            if isinstance(decoded_line, bytes):
                decoded_line = decoded_line.decode(part.get_content_charset(),'replace')

            text_parts.append((decoded_line, part.get_content_charset(), part.get_content_type()))

    return (text_parts)

def get_mime_struct(msg):

    mime_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition']
    mime_parts= OrderedDict()

    for part in msg.walk():
        #print("outer"+str(part))
        all_heads = [name.lower() for name in part.keys()]
        #print(all_heads)

        part_dict = {}
        part_key = 'text/plain'
        for head in filter(lambda n: all_heads.count(n), mime_heads):

            if head == 'content-type':

                part_key = part.get(head)
                part_key = part_key.partition(';')[0].strip()
                part_dict[head] = re.sub(part_key+';','',part.get(head),re.I)

            else:
                part_dict[head] = part.get(head)

        mime_parts[(part_key.partition(';')[0]).strip()] = part_dict

    return(mime_parts)

def get_nest_level(msg):

    mime_parts = get_mime_struct(msg)
    print(list(mime_parts.keys()))
    level = len(list(filter(lambda n: re.match('(multipart|message)',n,re.I), list(mime_parts.keys()))))

    return(level)

def get_url_list(msg):

    text_parts = get_text_parts(msg)
    #logger.debug("TEXT PARTS "+str(text_parts))
    url_list = []
    url_regexp= r'(((https?|ftps?):\/\/)|www:).*'
    for line, encoding, content_type in text_parts:

        #print(type(line))

        #logger.debug(str(('###'+line,)))
        if 'html' in content_type:

            soup = BeautifulSoup(line)
            if soup.a:
                url_list.extend(soup.a)
        else:

            url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split('\n')]))

    #logger.debug('URL LIST >>>> '+str(url_list))
    return(url_list)


if __name__ == "__main__":
    usage = "usage: %prog [ training_directory | file ] -b"
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument("PATH", type=str, help="path to collection dir or to email")
    parser.add_argument("-b", action = "store_true", default=False, help="show only bodies MIME structures")
    parser.add_argument("-stat", action = "store_true", default=False, help="print headers stat")
    args = parser.parse_args()

    tmp = '/tmp'
    formatter = logging.Formatter('%(message)s')
    logger = logging.getLogger()
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

        #print(pathes)
        common_heads_list = []
        for sample_path in pathes:
            with open(sample_path, 'rb') as f:
                msg = parser.parse(f)

            logger.debug('\nPATH: '+sample_path.upper()+'\n')

            filename = os.path.basename(sample_path)
            if not args.b:

                #logger.debug('\n============== common garden parser ====================\n')
                #headers_parser(cut_header_from_body(sample_path)[0], sample_path)

                logger.debug('\n============== parser from STL email ====================\n')
                for k in msg.keys():
                    if k == 'Subject':

                        subj_parts_list = [(l[0],(replace(l[1])).upper()) for l in decode_header(msg.get(k))]
                        logger.debug('HEADER( '+(filename)+' ):\t'+k+' ==> '+quote_the_value(subj_parts_list))

                    else:
                        logger.debug('HEADER( '+(filename)+' ):\t'+k+' ==> '+quote_the_value(str(msg.get(k))))

            heads_list = msg.keys()
            common_heads_list.extend([(name, heads_list.count(name)) for name in heads_list])


            logger.debug('PREAMBLE ( '+(filename)+' ): ==> '+quote_the_value(str(msg.preamble)))
            logger.debug('STRUCTURE')
            logger.debug('\t'+str(email.iterators._structure(msg)))
            logger.debug("IS_MULTIPART_FLAG = "+str(msg.is_multipart()))
            if msg.is_multipart():

                d = get_mime_struct(msg)
                logger.debug('=====================================')
                for k in d.keys():
                    logger.debug(k+' -- > '+str(d.get(k)))

                logger.debug('=====================================')

            logger.debug('EPILOGUE ( '+(filename)+' ): ==> '+quote_the_value(str(msg.epilogue)))
            logger.debug('==========URL_LIST==========')
            i = 0
            for l in get_url_list(msg):
                logger.debug('\t'+str(i)+'. >'+str(l)+'<')
                i +=1

            logger.debug('NEST LEVEL: '+str(get_nest_level(msg)))

        if args.stat:
            logger.debug('\n============== heads stat ====================\n')
            heads = [ i[0] for i in common_heads_list ]
            unique = tuple(set([ i[0] for i in common_heads_list ]))
            unique_list = list(zip(tuple([heads.count(u) for u in unique]),unique))

            unique_list.sort()


            for item in unique_list:
                value,key = item
                logger.debug(key+' --> '+str(value))



    except Exception as details:
        logger.error(str(details))
        raise

#TODO: analayze boundaries multipart/mixed;\n boundary="----_=_NextPart_27088_00010285.00024182 (consequences)