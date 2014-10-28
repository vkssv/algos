#! /usr/bin/env python

import sys, os, logging, re, email, argparse,time



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

    #for h_key in headers_dict.iterkeys():
    #    logger.debug('__HEADER__( '+(d)+' ):\t'+h_key+' --> '+quote_the_value(headers_dict.get(h_key)))

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


if __name__ == "__main__":
    usage = "usage: %prog [ training_directory | file ] -b"
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument("PATH", type=str, help="path to collection dir or to email")
    parser.add_argument("-b", action = "store_true", default=False, help="show only bodies MIME structures")
    args = parser.parse_args()

    tmp = '/tmp'
    formatter = logging.Formatter('%(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler(os.path.join(tmp, 'headers_'+time.strftime("%y%m%d_%H%M", time.localtime())+'.log'), mode = 'w')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    # 1. create train dataset
    try:
        parser = email.Parser.Parser()
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
            f = open(sample_path, 'rb')
            msg = parser.parse(f)
            f.close()
            logger.debug('\nPATH: '+sample_path)

            filename = os.path.basename(sample_path)
            if not args.b:

                logger.debug('\n============== common garden parser ====================\n')
                headers_parser(cut_header_from_body(sample_path)[0], sample_path)

                logger.debug('\n============== parser from STL email ====================\n')
                for k in msg.keys():
                    logger.debug('HEADER( '+(filename)+' ):\t'+k+' ==> '+quote_the_value(str(msg.get(k))))

            heads_list = msg.keys()
            common_heads_list.extend([(name, heads_list.count(name)) for name in heads_list])


            logger.debug('PREAMBLE ( '+(filename)+' ): ==> '+quote_the_value(str(msg.preamble)))
            logger.debug('STRUCTURE')
            if msg.is_multipart():
                get_mime_info(msg,filename)
            else:
                logger.debug(email.iterators._structure(msg))

            logger.debug('EPILOGUE ( '+(filename)+' ): ==> '+quote_the_value(str(msg.epilogue)))

        logger.debug('\n============== heads stat ====================\n')
        heads = [ i[0] for i in common_heads_list ]
        unique = tuple(set([ i[0] for i in common_heads_list ]))
        unique_list = zip(tuple([heads.count(u) for u in unique]),unique)
        unique_list.sort()


        for item in unique_list:
            value,key = item
            logger.debug(key+' --> '+str(value))

    except Exception, details:
        logger.error(str(details))
        raise

