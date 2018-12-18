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
  print('O token é opcional.\n')
  sys.exit(1)

print('Execução do GET\n')

if (len(argumentos) == 2):
    answerGET, options = c.GET(argumentos[1])
else:
    answerGET, options = c.GET(argumentos[1], token=argumentos[2])

print('- Reposta do GET:')
print(answerGET)
print(' ')
print('- Opções respondidas pelo servidor:')
print(options)
