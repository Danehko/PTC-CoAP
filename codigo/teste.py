import coapLD
import os
import sys

c = coapLD.coap()
c.GET(str.encode(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
