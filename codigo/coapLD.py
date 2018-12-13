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
	CONFIRMABLE = int(0)
	NONCONFIRMABLE = int(16)
	ACK = int(32)
	RESET = int(64)

class CODE_0(Enum):
	EMPTY_MSG = int(0)
	GET = int(1)
	POST = int(2)
	PUT = int(3)
	DELETE = int(4)

class CODE_2(Enum):
	CREATED = int(65)
	DELETED = int(66)
	VALID = int(67)
	CHANGED = int(68)
	CONTENT = int(69)

class CODE_4(Enum):
	BADREQUEST = int(128)
	UNAUTHORIZED = int(129)
	BADOPTION = int(130)
	FORBIDDEN = int(131)
	NOTFOUND = int(132)
	METHODNOTALLOWED = int(133)
	NOTACCEPTABLE = int(134)
	PRECONDITIONFAILED = int(140)
	REQUESTENTITYTOOLARGE = int(141)
	UNSUPPORTEDFORMAT = int(143)

class CODE_5(Enum):
	INTERNALSERVERFAILED = int(192)
	NOTIMPLEMENT = int(193)
	BADGATEWAY = int(194)
	SERVICEUNAVAILABLE = int(195)
	GATEWAYTIMEOUT = int(196)
	PROXYINGNOTSUPPORTED = int(197)

class DELTA(Enum):
	IFMATCH = int(16) #0001 0000
	URI_HOST = int(48) #0011 0000
	ETAG = int(64) #0100 0000
	IF_NONE_MATCH = int(80) # 0101 0000
	URI_PORT = int(112)#0111
	LOCATION_PATH = int(128)
	URI_PATH = int(176)#1011 0000
	CONTENT_FORMAT = int(192)#1100 0000
	MAX_AGE = int(224)#1110 0000
	URI_QUERY = int(240) 
	#arrumar
	ACCEPT = int(17)
	LOCATION_QUERY = int(20)
	PROXY_URI = int(35)
	PROXY_SCHEME = int(39)
	SIZE1 = int(60)

class coap:

	def __init__(self):
		self.versao = int(64) # sempre 01000000
		self.tipo = int(0)
		self.tkl = int(0) #  tkl é sempre 00000000.
		self.code = int(0)
		self.messageID1 = int(35)
		self.messageID2 = int(89)
		self.optionsdelta = int(48)
		self.optionslength = int(0)
		self.options = int(0) # campo de valor variavel.
		#self.acesscode = int(255) # playload_mac e sempre ff.
		self.payload = b''
		self.quadro = b''
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		#self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#self.sock.bind((socket.gethostname(), 5555))

	def QUADRO(self):
		self.quadro = b''
		#self.quadro += (bytes([self.versao + self.tipo + self.tkl]))
		self.quadro += bytes([self.versao + self.tipo + self.tkl])
		print(self.quadro)
		self.quadro += bytes([self.code])
		print(self.quadro)
		self.quadro += bytes([self.messageID1])
		print(self.quadro)
		self.quadro += bytes([self.messageID2])
		print(self.quadro)
		self.quadro += bytes([self.optionsdelta + self.optionslength])
		print(self.quadro)
		self.quadro += self.options
		print(self.quadro)
		#self.quadro += bytes([self.acesscode])
		self.quadro += self.payload
		print(self.quadro)

	def GET(self, uri_path, server_adress, port):
		self.tipo = T.CONFIRMABLE.value
		self.code = CODE_0.GET.value
		self.optionsdelta = DELTA.URI_HOST.value
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.QUADRO()
		print(self.quadro)

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
