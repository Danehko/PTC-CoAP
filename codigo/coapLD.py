from itertools import chain
import codecs
import collections
import copy
import random
import struct
import sys
import socket

from enum import Enum

class T(Enum):
	CONFIRMABLE = b'\x00'       #00 00 0000
	NONCONFIRMABLE = b'\x01'   #00 01 0000
	ACK = b'\x02'              #00 10 0000
	RESET = b'\x03'            #00 11 0000

class CODE_0(Enum): #requisição
	EMPTY_MSG = b'\x00'
	GET = b'\x01'
	POST = b'\x02'
	PUT = b'\x03'
	DELETE = b'\x04'

class CODE_2(Enum): #
	CREATED = b'\x41' # 0100 0001 - 65  
	DELETED = b'\x42' # 0100 0010 - 66
	VALID = b'\x43'   # 0100 0011 - 67 
	CHANGED = b'\x44' # 0100 0100 - 67
	CONTENT = b'\x45' # 0100 0101 - 69

class CODE_4(Enum):
	BADREQUEST = b'\x80' # 1000 0000
	UNAUTHORIZED = b'\x81' # 1000 0001
	BADOPTION = b'\x82' # 1000 0010
	FORBIDDEN = b'\x83' # 1000 0011
	NOTFOUND = b'\x84' #  1000 0100
	METHODNOTALLOWED = b'\x85' # 1000 0101
	NOTACCEPTABLE = b'\x86' # 1000 0110
	PRECONDITIONFAILED = b'\x8C' # 1000 1101
	REQUESTENTITYTOOLARGE = b'\x8D' # 1000 1110
	UNSUPPORTEDFORMAT = b'\x8F' # 1000 1111
	
class CODE_5(Enum):
	INTERNALSERVERFAILED = b'\xA0' #
	NOTIMPLEMENT = b'\xA1' #
	BADGATEWAY = b'\xA2' #
	SERVICEUNAVAILABLE = b'\xA3' #
	GATEWAYTIMEOUT = b'\xA4' #
	PROXYINGNOTSUPPORTED = b'\xA5' #

class DELTA(Enum):
	IF_MATC =  b'\x01'
	URI_HOST =  b'\x03'
	ETAG =  b'\x04'
	IF_NONE_MATCH =  b'\x05'
	URI_PORT =  b'\x07'
	LOCATION_PATH =  b'\x08'
	URI_PATH =  b'\x0B'
	CONTENT_FORMAT =  b'\x0C'
	MAX_AGE =  b'\x0E'
	URI_QUERY =  b'\x0F'
	ACCEPT =  b'\x11'
	LOCATION_QUERY =  b'\x14'
	PROXY_URI =  b'\x23'
	PROXY_SCHEME =  b'\x27'
	SIZE1 = B'\x3C'
	
class coap:

	def __init__(self):
		self.versao = b'\x01'
		self.tipo = b'\00'
		self.tkl = b'\x00' #  tkl é sempre 00000000.
		self.code = b'\x00'
		self.messageID1 = b'\x35'
		self.messageID2 = b'\x89'
		self.optionsdelta = b'\x00'
		self.optionslength = b'\x00'
		self.options = b'\x00' # campo de valor variavel.
		self.acesscode = b'\xff' # playload_mac e sempre ff.
		self.payload = b''
		self.quadro = b''
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		
	def QUADRO(self):
		self.quadro = b''
		self.quadro += ((self.versao[0] << 6) | (self.tipo[0] << 4) | (self.tkl[0])).to_bytes(1, byteorder='big')
		print(self.quadro)
		self.quadro += self.code
		print(self.quadro)
		self.quadro += self.messageID1
		print(self.quadro)
		self.quadro += self.messageID2
		print(self.quadro)
		self.quadro += ((self.optionsdelta[0] << 4) | (self.optionslength)).to_bytes(1, byteorder='big')
		print(self.quadro)
		self.quadro += self.options
		print(self.quadro)
		if ((self.code  == CODE_0.POST.value) or (self.code  == CODE_0.PUT.value)):
		  self.quadro += bytes([self.acesscode])
		self.quadro += self.payload
		print(self.quadro)

	def GET(self, uri_path, server_adress, port):
		self.tipo = T.CONFIRMABLE.value
		self.code = CODE_0.GET.value
		self.optionsdelta = DELTA.URI_HOST.value
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.payload = b''
		self.QUADRO()

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

	def POST(self, uri_path, server_adress, port):
		self.tipo = T.CONFIRMABLE.value
		self.code = CODE_0.POST.value
		self.optionsdelta = DELTA.URI_PATH.value
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.payload = b'XABLAU'
		self.QUADRO()
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

	def PUT(self, uri_path, server_adress, port):
		self.tipo = T.CONFIRMABLE.value
		self.code = CODE_0.PUT.value
		self.optionsdelta = DELTA.URI_PATH.value
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.payload = b'XABLAU'
		self.QUADRO()
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

	def DELETE(self, uri_path, server_adress, port):
		self.tipo = T.CONFIRMABLE.value
		self.code = CODE_0.DELETE.value
		self.optionsdelta = DELTA.URI_PATH.value
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.QUADRO()
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)
