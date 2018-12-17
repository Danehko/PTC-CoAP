import coapLD
import os
import sys

c = coapLD.coap()

argumentos = sys.argv[0:]

if (len(argumentos) < 2):
  print('Para executar esse teste é preciso digitar: ')
  print('- O recurso, que pode ser escrito de várias formas: ')
  print('   Ex: ')
  print('     - coap://127.0.0.1:5683/.well-known/core')
  print('     - coap://127.0.0.1/.well-known/core')
  print('     - coap://localhost/.well-known/core')
  print('- O token: 123')
  print('O token é opcional.')
  sys.exit(1)

print('Execução do PUT')

inp = input("Digite o payload:\n")

answerPUT = c.PUT(argumentos[1], inp=inp)

print('\nReposta do PUT:')
print(answerPUT)