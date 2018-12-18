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
  print('A porta e o token são opcionais.\n')
  print('O token só funciona se tiver a porta nesse método.\n')
  sys.exit(1)

print('Execução do GET\n')

if (len(argumentos) == 4):
    answerGET, options = c.GET(argumentos[1], argumentos[2], int(argumentos[3]))
elif (len(argumentos) == 5):
    answerGET, options = c.GET(argumentos[1], argumentos[2], int(argumentos[3]), str(argumentos[4]))
else:
    answerGET, options = c.GET(argumentos[1], argumentos[2])

print('- Reposta do GET:')
print(answerGET)
print(' ')
print('- Opções respondidas pelo servidor:')
print(options)
