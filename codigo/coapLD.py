from itertools import chain
import codecs
import collections
import copy
import random
import struct
import sys
import socket

from enum import Enum

class T(Enum): #tipo
	CONFIRMABLE = b'\x00'       #00 00 0000
	NONCONFIRMABLE = b'\x01'   #00 01 0000
	ACK = b'\x02'              #00 10 0000
	RESET = b'\x03'            #00 11 0000

class CODE_0(Enum): #codigo de requisição
	EMPTY_MSG = b'\x00'
	GET = b'\x01'
	POST = b'\x02'
	PUT = b'\x03'
	DELETE = b'\x04'

class CODE_2(Enum): # #codigo de resposta sucesso
	CREATED = b'\x41' # 0100 0001 - 65  
	DELETED = b'\x42' # 0100 0010 - 66
	VALID = b'\x43'   # 0100 0011 - 67 
	CHANGED = b'\x44' # 0100 0100 - 67
	CONTENT = b'\x45' # 0100 0101 - 69

class CODE_4(Enum): #codigo de erro de cliente
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
	
class CODE_5(Enum): #codigo de erro de servidor
	INTERNALSERVERFAILED = b'\xA0' #
	NOTIMPLEMENT = b'\xA1' #
	BADGATEWAY = b'\xA2' #
	SERVICEUNAVAILABLE = b'\xA3' #
	GATEWAYTIMEOUT = b'\xA4' #
	PROXYINGNOTSUPPORTED = b'\xA5' #

class DELTA(Enum): #opção delta
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
		self.versao = b'\x01' #padrão 01, só existe uma versao de coap
		self.tipo = b'\00'
		self.tkl = b'\x00' #token length é sempre 00000000.
		self.token = b'' 
		self.code = b'\x00' # codigo
		self.messageID1 = b'\x35'
		self.messageID2 = b'\x89' # messagem id usado para detectar duplicatas e para confiabilidade opcional
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
		self.quadro += self.code
		self.quadro += self.messageID1
		self.quadro += self.messageID2
		self.quadro += ((self.optionsdelta[0] << 4) | (self.optionslength)).to_bytes(1, byteorder='big')
		self.quadro += self.options
		if ((self.code  == CODE_0.POST.value) or (self.code  == CODE_0.PUT.value)):
		  self.quadro += bytes([self.acesscode])
		self.quadro += self.payload
		print(self.quadro)
		
	def recebe(self, quadro_recebido):
		primeiro_byte = quadro_recebido[0]
		versao_rec = primeiro_byte & ((2**7)+(2**6))
		tipo_rec = primeiro_byte & ((2**5)+(2**4))
		tkl_rec = primeiro_byte & ((2**3)+(2**2)+(2**1)+(2**0))
		quadro_recebido = quadro_recebido[1:]
		if(versao_rec == (2**6)):
			if(tipo_rec == (2**5)):
				codigo_rec = quadro_recebido[0]
				quadro_recebido = quadro_recebido[1:]
				if(codigo_rec == 128):
					return '4.00 - Bad Request'
				if(codigo_rec == 129):
					return '4.01 - Unauthorized'
				if(codigo_rec == 130):
					return '4.02 - Bad Option'
				if(codigo_rec == 131):
					return '4.03 - Forbidden'
				if(codigo_rec == 132):
					return '4.04 - Not Found'
				if(codigo_rec == 133):
					return '4.05 - Method Not Allowed'
				if(codigo_rec == 134):
					return '4.06 - Not Acceptable'
				if(codigo_rec == 140):
					return '4.12 - Precondition Failed'
				if(codigo_rec == 141):
					return '4.13 - Request Entity Too Large'
				if(codigo_rec == 143):
					return '4.15 - Unsupported Content-Format'
				if(codigo_rec == 160):
					return '5.00 - Internal Server Error'
				if(codigo_rec == 161):
					return '5.01 - Not Implemented'
				if(codigo_rec == 162):
					return '5.02 - Bad Gateway'
				if(codigo_rec == 163):
					return '5.03 - Service Unavailable'
				if(codigo_rec == 164):
					return '5.04 - Gateway Timeout'
				if(codigo_rec == 165):
					return '5.05 - Proxying Not Supported'
				if(codigo_rec >= 65 and codigo <= 69):
					messageID_rec = quadro_recebido[0:2]
					quadro_recebido = quadro_recebido[2:]
					messadeID = b''
					messadeID += self.messageID1
					messadeID += self.messageID2
					if(messageID_rec == messageID):	
						quadro_recebido = quadro_recebido[tkl_rec:]
						aux = True
						while aux:
							op_delta_length = quadro_recebido[0]
							quadro_recebido = quadro_recebido[1:]
							op_delta = op_delta_length & ((2**7)+(2**6)+(2**5)+(2**4))
							op_length = op_delta_length & ((2**3)+(2**2)+(2**1)+(2**0))
							op_delta = quadro_recebido >> 4
							if (op_delta == 13):
								op_delta = quadro_recebido[0]
								quadro_recebido = quadro_recebido[1:]
							if (op_delta == 14):
								op_delta = quadro_recebido[0:2]
								quadro_recebido = quadro_recebido[2:]
							if (op_delta == 15):
								if (op_length != 15):
									return ('ERRo')
								else:
									aux = False
								payload = quadro_recebido
							if (op_delta < 13):		
								if (op_length == 13):
									op_length = quadro_recebido[0]
									quadro_recebido = quadro_recebido[1:]
								if (op_length == 14):
									op_length = quadro_recebido[0:2]
									quadro_recebido = quadro_recebido[2:]
								if (op_length == 15):
									return (ERRO)
								option = quadro_recebido[0:op_length]
						if(codigo_rec == 65):
							return '2.01 - Created ' + payload.decode("utf-8")
						if(codigo_rec == 66):
							return '2.02 - Deleted ' + payload.decode("utf-8")
						if(codigo_rec == 67):
							return '2.03 - Valid ' + payload.decode("utf-8")
						if(codigo_rec == 68):
							return '2.04 - Changed ' + payload.decode("utf-8")
						if(codigo_rec == 69):
							return '2.05 - Content ' + payload.decode("utf-8")
					return 'Erro - Mensagem Id não compativel'
				return 'Codigo desconhecido'
			return 'Tipo não esperado'
		return 'versao inesistente'

	def GET(self, uri_path, server_adress, port):
		self.tipo = T.CONFIRMABLE.value
		self.code = CODE_0.GET.value
		self.optionsdelta = DELTA.URI_HOST.value
		self.optionslength = len(uri_path)
		self.options = uri_path
		self.payload = b''
		self.QUADRO()
		
		#resource_list = resource.split('/')
		#for uri_path in  resource_list:
		#	if(self.opcao_delta > 0):
		#		self.opcao_delta -= OPTIONS_DELTA.URI_PATH.value[0]
		#	else:
		#		self.opcao_delta = OPTIONS_DELTA.URI_PATH.value[0]
		#	if(self.opcao_delta < 0):
		#		self.opcao_delta = 0
		#		
		#	self.quadro += (self.opcao_delta << 4 | len(uri_path)).to_bytes(1, byteorder='big')
		#	print(uri_path.encode())
		#self.quadro += str.encode(uri_path)

		self.sock.sendto(self.quadro, (server_adress, port))
		data, addr = self.sock.recvfrom(1024)
		
		resposta = self.recebe(data)
		print(resposta)

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
