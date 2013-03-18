#!/usr/bin/env python

# Raw Socket
# Edited by Mar, 12

# TCP

import sys
import urllib
import rawurllib
import rawsocket
import re

def usage():
    print "Usage: rawhttpget [URL]"

def main():
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)
    
    url = sys.argv[1] 
    rawurllib.urlretrieve(url, rawurllib.getname(url))


if __name__ == "__main__":
    main()


