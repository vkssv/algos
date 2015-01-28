#!/usr/bin/env python

import sys, os, re
from optparse import OptionParser

if __name__ == "__main__":

	usage = "usage: %prog [options] -d collection_dir"
	parser = OptionParser(usage)

	parser.add_option("-d", action="store", type="string", dest="dir", metavar=" ", help="path to dir with spam/ham collections", default=os.getcwd())

	(options, args) = parser.parse_args()

        try:
	        if options.dir == os.getcwd():
                        print(">> Will rename all *.eml files in current dir, are you agree ? [N]")
                        line = raw_input(">> ")

                        if not line or re.match("(No|n)$", line.strip(),re.I):
                                sys.exit(0)

                i = 0
                for file in os.listdir(options.dir):
                        if os.path.getsize(os.path.join(options.dir,file)) !=0:
                                os.rename(os.path.join(options.dir,file),os.path.join(options.dir,(str(i)+'.eml')))
                                i +=1
                        else:
                                os.unlink(os.path.join(options.dir,file))

        except KeyboardInterrupt, details:
                sys.exit(0)

        except Exception, details:
                print(str(details))
                sys.exit(1)