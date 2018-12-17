#!/usr/bin/python3

from itertools import chain
import codecs
import collections
import copy
import random
import struct
import sys
import socket
from enum import Enum

# tipo de mensagem
class TYPE(Enum):
  CONFIRMABLE = b'\x00'      #00 00 0000
  NONCONFIRMABLE = b'\x01'   #00 01 0000
  ACK = b'\x02'              #00 10 0000
  RESET = b'\x03'            #00 11 0000

# código de requisição
class CODE_REQUEST(Enum):
  EMPTY_MSG = b'\x00'
  GET = b'\x01'
  POST = b'\x02'
  PUT = b'\x03'
  DELETE = b'\x04'

# código de resposta sucesso
class CODE_SUCCESS(Enum):
  CREATED = b'\x41' # 0100 0001 - 65  
  DELETED = b'\x42' # 0100 0010 - 66
  VALID = b'\x43'   # 0100 0011 - 67 
  CHANGED = b'\x44' # 0100 0100 - 67
  CONTENT = b'\x45' # 0100 0101 - 69

# código de erro de cliente
class CODE_CLIENT_ERROR(Enum):
  BAD_REQUEST = b'\x80'                 # 1000 0000
  UNAUTHORIZED = b'\x81'                # 1000 0001
  BAD_OPTION = b'\x82'                  # 1000 0010
  FORBIDDEN = b'\x83'                   # 1000 0011
  NOT_FOUND = b'\x84'                   # 1000 0100
  METHOD_NOT_ALLOWED = b'\x85'          # 1000 0101
  NOT_ACCEPTABLE = b'\x86'              # 1000 0110
  PRECONDITION_FAILED = b'\x8C'         # 1000 1101
  REQUEST_ENTITY_TOO_LARGE = b'\x8D'    # 1000 1110
  UNSUPPORTED_CONTENT_FORMAT = b'\x8F'  # 1000 1111

# código de erro de servidor
class CODE_SERVER_ERROR(Enum):
  INTERNAL_SERVER_FAILED = b'\xA0'
  NOT_IMPLEMENT = b'\xA1'
  BAD_GATEWAY = b'\xA2'
  SERVICE_UNAVAILABLE = b'\xA3'
  GATEWAY_TIMEOUT = b'\xA4'
  PROXYING_NOT_SUPPORTED = b'\xA5'

# opção delta
class OPTIONS_DELTA(Enum):
  IF_MATC = b'\x01'
  URI_HOST = b'\x03'
  ETAG = b'\x04'
  IF_NONE_MATCH = b'\x05'
  URI_PORT = b'\x07'
  LOCATION_PATH = b'\x08'
  URI_PATH = b'\x0B'
  CONTENT_FORMAT = b'\x0C'
  MAX_AGE = b'\x0E'
  URI_QUERY = b'\x0F'
  ACCEPT = b'\x11'
  LOCATION_QUERY = b'\x14'
  PROXY_URI = b'\x23'
  PROXY_SCHEME = b'\x27'
  SIZE1 = b'\x3C'
	
class coap:

  def __init__(self):
    # valor padrão: 01
    # só existe uma versão de CoAP
    self.version = b'\x01'
    # tipo de mensagem
    self.type = b'\00'
    # nesse projeto token length é sempre 00000000
    self.tkl = b'\x00'
    # usado para transmissão multi ponto
    self.token = b''
    # código
    self.code = b'\x00'
    # messagem ID usado para detectar duplicatas e para confiabilidade opcional
    self.messageIDmsb = b'\x35'
    self.messageIDlsb = b'\x89' 
    self.optionsdelta = b'\x00'
    self.optionsdeltaold = int(0)
    self.optionslength = b'\x00'
    # campo de valor variável
    self.options = b'\x00' 
    # delimitador de quadro início de payload (PUT e POST)
    # accesscode e sempre \xFF
    self.accesscode = b'\xff'
    # dado
    self.payload = b''
    # pacote pronto para envio
    self.frame = b''
    # método de envio
    self.method = 'direct'
    # IP ou DNS
    self.path = ''
    # porta
    self.port = int(5683)
    # socket UDP
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	

  def GET(self, resource, server_adress='', port=int(5683)):
    self.type = TYPE.CONFIRMABLE.value
    self.code = CODE_REQUEST.GET.value
    self.payload = b''
    self.method = 'direct'
    
    if server_adress != '':
      self.path = server_adress
      self.port = port
      self.method = 'not_direct'
      
    self.generateFrame(resource)
    self.sock.sendto(self.frame, (self.path, self.port))
    data, addr = self.sock.recvfrom(1024)

    answer = self.receive(data)
    print(answer)


  def DELETE(self, resource, server_adress='', port=int(5683)):
    self.type = TYPE.CONFIRMABLE.value
    self.code = CODE_REQUEST.GET.value
    self.payload = b''
    self.method = 'direct'

    if server_adress != '':
      self.path = server_adress
      self.port = port
      self.method = 'not_direct'

    self.generateFrame(resource)
    self.sock.sendto(self.frame, (self.path, self.port))
    data, addr = self.sock.recvfrom(1024)

    answer = self.receive(data)
    print(answer)


  def POST(self, resource, server_adress='', port=int(5683), inp=''):
    self.type = TYPE.CONFIRMABLE.value
    self.code = CODE_REQUEST.POST.value
    self.payload = inp.encode()
    self.method = 'direct'

    if server_adress != '':
      self.path = server_adress
      self.port = port
      self.method = 'not_direct'
      
    self.generateFrame(resource)
    self.sock.sendto(self.frame, (self.path, self.port))
    data, addr = self.sock.recvfrom(1024)

    answer = self.receive(data)
    print(answer)


  def PUT(self, resource, server_adress='', port=int(5683), inp=''):
    print(inp)
    self.type = TYPE.CONFIRMABLE.value
    self.code = CODE_REQUEST.PUT.value
    self.payload = inp.encode()
    self.method = 'direct'

    if server_adress != '':
      self.path = server_adress
      self.port = port
      self.method = 'not_direct'
      
    self.generateFrame(resource)    
    self.sock.sendto(self.frame, (self.path, self.port))
    data, addr = self.sock.recvfrom(1024)

    answer = self.receive(data)
    print(answer)


  def generateFrame(self, resource):
    self.frame = b''
    self.frame += ((self.version[0] << 6) | (self.type[0] << 4) | (self.tkl[0])).to_bytes(1, byteorder='big')
    self.frame += self.code
    self.frame += self.messageIDmsb
    self.frame += self.messageIDlsb
    if(self.method == 'not_direct'):
      resource_list = resource.split('/')
      for uri_path in resource_list:
        self.optionsdelta = OPTIONS_DELTA.URI_PATH.value[0] - self.optionsdeltaold
        self.optionsdeltaold = OPTIONS_DELTA.URI_PATH.value[0]
        self.optionslength = len(uri_path)
        self.frame += (self.optionsdelta << 4 | self.optionslength).to_bytes(1, byteorder='big')
        self.frame += str.encode(uri_path)
      if ((self.code  == CODE_REQUEST.POST.value) or (self.code  == CODE_REQUEST.PUT.value)):
        self.frame += bytes(self.accesscode)
        self.frame += self.payload
      return
    elif(self.method == 'direct'):
      if (resource[0:7] != 'coap://'):
        return 'ERRO'
      parameters = resource[7:].split('/')
      addr = parameters[0].split(':')
      self.optionslength = len(addr[0])
      if (len(addr) > 1):
        self.port = int(addr[1])
      addr = addr[0].split('.')
      if (not(len(addr)==4 and addr[0].isnumeric and addr[1].isnumeric and addr[2].isnumeric and addr[3].isnumeric)):
        self.optionsdelta = OPTIONS_DELTA.URI_HOST.value[0] - self.optionsdeltaold
        self.optionsdeltaold = OPTIONS_DELTA.URI_HOST.value[0]
        self.frame += (self.optionsdelta << 4 | self.optionslength).to_bytes(1, byteorder='big')
        self.frame += str.encode(addr[0])
      resource_list = parameters[1:]
      for uri_path in resource_list:
        self.optionsdelta = OPTIONS_DELTA.URI_PATH.value[0] - self.optionsdeltaold
        self.optionsdeltaold = OPTIONS_DELTA.URI_PATH.value[0]
        self.optionslength = len(uri_path)
        self.frame += (self.optionsdelta << 4 | self.optionslength).to_bytes(1, byteorder='big')
        self.frame += str.encode(uri_path)
      if ((self.code  == CODE_REQUEST.POST.value) or (self.code  == CODE_REQUEST.PUT.value)):
        self.frame += bytes(self.accesscode)
        self.frame += self.payload
      return


  def receive(self, receivedFrame):
    first_byte = receivedFrame[0]
    version_rec = first_byte & ((2 ** 7) + (2 ** 6))
    type_rec = first_byte & ((2 ** 5) + (2 ** 4))
    tkl_rec = first_byte & ((2 ** 3) + (2 ** 2) + (2 ** 1) + (2 ** 0))
    receivedFrame = receivedFrame[1:]
    if (version_rec == (2 ** 6)):
      if (type_rec == (2 ** 5)):
        code_rec = receivedFrame[0]
        receivedFrame = receivedFrame[1:]
        if (code_rec >= 128 and code_rec <= 165):
          return self.error(code_rec)
        elif (code_rec >= 65 and code_rec <= 69):
          return self.success(code_rec, receivedFrame, tkl_rec)
        return 'Código desconhecido'
      return 'Tipo não esperado'
    return 'Versão inexistente'


  def success(self, code_rec, receivedFrame, tkl_rec):
    messageID_rec = receivedFrame[0:2]
    receivedFrame = receivedFrame[2:]
    messageID = b''
    messageID += self.messageIDmsb
    messageID += self.messageIDlsb

    if (messageID_rec == messageID):
      receivedFrame = receivedFrame[tkl_rec:]

      while (True):
        op_delta_length = receivedFrame[0]
        receivedFrame = receivedFrame[1:]
        op_delta = op_delta_length & 240
        op_delta = op_delta >> 4
        op_length = op_delta_length & 15
        
        if (op_delta < 13):
          if (op_length == 13):
            op_length = receivedFrame[0]
            op_length = ord(op_length) + 13
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[1:]
          elif (op_length == 14):
            op_length = receivedFrame[0:2]
            print(int.from_bytes(op_length, byteorder='big'))
            op_length = int.from_bytes(op_length, byteorder='big') + 269
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[2:]
          elif (op_length == 15):
            return ('ERRO')
          else:
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[op_length:]

        elif (op_delta == 13):
          op_delta = receivedFrame[0]
          receivedFrame = receivedFrame[1:]
          
          if (op_length == 13):
            op_length = receivedFrame[0]
            op_length = ord(op_length) + 13
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[1:]
          elif (op_length == 14):
            op_length = receivedFrame[0:2]
            print(int.from_bytes(op_length, byteorder='big'))
            op_length = int.from_bytes(op_length, byteorder='big') + 269
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[2:]
          elif (op_length == 15):
            return ('ERRO')
          else:
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[op_length:]

        elif (op_delta == 14):
          op_delta = receivedFrame[0:2]
          receivedFrame = receivedFrame[2:]
          
          if (op_length == 13):
            op_length = receivedFrame[0]
            op_length = ord(op_length) + 13
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[1:]
          elif (op_length == 14):
            op_length = receivedFrame[0:2]
            print(int.from_bytes(op_length, byteorder='big'))
            op_length = int.from_bytes(op_length, byteorder='big') + 269
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[2:]
          elif (op_length == 15):
            return ('ERRO')
          else:
            option = receivedFrame[0:op_length]
            receivedFrame = receivedFrame[op_length:]

        elif (op_delta == 15):
          if (op_length != 15):
            return ('ERRO')
          else:
            payload_rec = receivedFrame
            break

      if (code_rec == 65):
        return '2.01 - Created ' + payload_rec.decode("utf-8")
      elif (code_rec == 66):
        return '2.02 - Deleted ' + payload_rec.decode("utf-8")
      elif (code_rec == 67):
        return '2.03 - Valid ' + payload_rec.decode("utf-8")
      elif (code_rec == 68):
        return '2.04 - Changed ' + payload_rec.decode("utf-8")
      elif (code_rec == 69):
        return '2.05 - Content ' + payload_rec.decode("utf-8")

    return 'Erro - ID de Mensagem não compatível'


  def error(self, code_rec):
    if (code_rec == 128):
      return '4.00 - Bad Request'
    elif (code_rec == 129):
      return '4.01 - Unauthorized'
    elif (code_rec == 130):
      return '4.02 - Bad Option'
    elif (code_rec == 131):
      return '4.03 - Forbidden'
    elif (code_rec == 132):
      return '4.04 - Not Found'
    elif (code_rec == 133):
      return '4.05 - Method Not Allowed'
    elif (code_rec == 134):
      return '4.06 - Not Acceptable'
    elif (code_rec == 140):
      return '4.12 - Precondition Failed'
    elif (code_rec == 141):
      return '4.13 - Request Entity Too Large'
    elif (code_rec == 143):
      return '4.15 - Unsupported Content-Format'
    elif (code_rec == 160):
      return '5.00 - Internal Server Error'
    elif (code_rec == 161):
      return '5.01 - Not Implemented'
    elif (code_rec == 162):
      return '5.02 - Bad Gateway'
    elif (code_rec == 163):
      return '5.03 - Service Unavailable'
    elif (code_rec == 164):
      return '5.04 - Gateway Timeout'
    elif (code_rec == 165):
      return '5.05 - Proxying Not Supported'
    else:
      return 'Código desconhecido'
