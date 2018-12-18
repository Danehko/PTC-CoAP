import coapLD
import os
import sys

c = coapLD.coap()

argumentos = sys.argv[0:]

if (len(argumentos) < 2):
  print('Para executar esse teste é preciso digitar: ')
  print('   - O recurso: other/block')
  print('   - O IP: 127.0.0.1')
  print('   - A porta: 5683')
  print('A porta é opcional.')
  sys.exit(1)

print('Execução do PUT')

inp = input("Digite o payload:\n")

if (len(argumentos) == 4):
    answerPUT = c.PUT(argumentos[1], argumentos[2], int(argumentos[3]), inp)
else:
    answerPUT = c.PUT(argumentos[1], argumentos[2], inp=inp)

print('\nReposta do PUT:')
print(answerPUT)
