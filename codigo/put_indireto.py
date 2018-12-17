import coapLD
import os
import sys

c = coapLD.coap()

argumentos = sys.argv[0:]

if (len(argumentos) < 2):
  print('Para executar esse teste é preciso digitar: ')
  print('   - O recurso: .well-known/core')
  print('   - O IP: 127.0.0.1')
  print('   - A porta: 5683')
  print('   - O token: 123')
  print('A porta e o token são opcionais.')
  sys.exit(1)

print('Execução do PUT')

inp = input("Digite o payload:\n")

if (len(argumentos) == 4):
    answerPUT = c.PUT(argumentos[1], argumentos[2], int(argumentos[3]), inp)
else:
    answerPUT = c.PUT(argumentos[1], argumentos[2], inp=inp)

print('\nReposta do PUT:')
print(answerPUT)