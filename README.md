# Laboratório 2 de SSI

Este projeto tem como base a implementação do seguinte protocolo:

```
1. Alice faz GET_CERTIFICATE ao Bob
2. Bob faz SEND_CERTIFICATE à Alice
3. Bob envia certificado do Bob à Alice
4. Alice cria chave secreta SK
5. Alice encripta SK com chave publica do Bob
6. Alice faz SECRET_KEY ao Bob
7. Alice envia PARAMS ao Bob
8. Alice envia SK encriptada com a chave publica do Bob ao Bob
9. Bob decifra SK com chave privada do Bob
10. Bob encripta mensagem com SK
11. Bob envia mensagem encriptada com SK
12. Alice decifra mensagem com SK
13. Alice cria chave secreta SK2
14. Alice faz RENEW_SECRET_KEY ao Bob
15. Alice encripta SK2 com chave pública do Bob
16. Alice envia SK2 encriptada com a chave pública do Bob
17. Bob decifra SK2 com chave privada do Bob
18. Bob encripta a mensagem com SK2
19. Bob envia mensagem encriptada com SK2 à Alice
20. Alice decifra mensagem com SK2.
```

### Instruções ###

- Fazer ```pip install -r requirements.txt```
- Iniciar [Bob.py](Bob.py)
- Iniciar [Alice.py](Alice.py)

