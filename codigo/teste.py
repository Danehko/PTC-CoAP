import coapLD
import os
import sys

c = coapLD.coap()
#c.GET(sys.argv[1], sys.argv[2], int(sys.argv[3]))
c.PUT(sys.argv[1], inp=sys.argv[2])
