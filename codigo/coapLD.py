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
	IFMATCH = int(1)
	URI_HOST = int(3)
	ETAG = int(4)
	IF_NONE_MATCH = int(5)
	URI_PORT = int(7)
	LOCATION_PATH = int(8)
	URI_PATH = int(11)
	CONTENT_FORMAT = int(12)
	MAX_AGE = int(14)
	URI_QUERY = int(15)
	ACCEPT = int(17)
	LOCATION_QUERY = int(20)
	PROXY_URI = int(35)
	PROXY_SCHEME = int(39)
	SIZE1 = int(60)

class coap:

	def __init__(self):
		self.v = int(64) # sempre 01000000
		self.t = int(0)
		self.tkl = int(0) #  tkl é sempre 00000000.
		self.code = int(0)
		self.messageID = int(10285)
		self.optionsdelta = int(0)
		self.optionslength = int(0)
		self.options = int(0) # campo de valor variavel.
		self.acesscode = int(255) # playload_mac e sempre ff.
		self.payload = b''
		self.quadro = b''
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		#self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#self.sock.bind((socket.gethostname(), 5555))

	def QUADRO(self):
		self.quadro = b''
		self.quadro += (bytes([self.versao + self.tipo + self.tkl]))
		self.quadro += (bytes([self.versao + self.tipo + self.tkl]))
		self.quadro += (bytes([self.code.value]))
		self.quadro += (bytes([self.messageID]))
		self.quadro += (bytes([self.optionsdelta + self.optionslength])) 
		self.quadro += (bytes([self.options]))
		self.quadro += (bytes([self.acesscode]))
		self.quadro += (bytes([self.payload]))

	def GET(self, uri_path, server_adress, port):
		self.t = T.CONFIRMABLE
		self.code = CODE_0.GET
		self.optionsdelta = DELTA.URI_PATH
		self.optionslength = len(uri_path)
		self.options = uri_path
		QUADRO(self)
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

	def POST(self, uri_path, server_adress, port):
		self.t = T.CONFIRMABLE
		self.code = CODE_0.POST
		self.optionsdelta = DELTA.URI_PATH
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.payload = b'XABLAU'
		QUADRO(self)
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

	def PUT(self, uri_path, server_adress, port):
		self.t = T.CONFIRMABLE
		self.code = CODE_0.PUT
		self.optionsdelta = DELTA.URI_PATH
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.payload = b'XABLAU'
		QUADRO(self)
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

		

	def DELETE(self, uri_path, server_adress, port):
		self.t = T.CONFIRMABLE
		self.code = CODE_0.DELETE
		self.optionsdelta = DELTA.URI_PATH
		self.optionslength = len(uri_path)
		self.options = uri_path
		QUADRO(self)
		print(self.quadro)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		print(data)
		print(addr)

