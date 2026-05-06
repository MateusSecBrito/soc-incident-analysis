# Phishing com execução de comandos de reconhecimento

## Situação
- Foi enviado um e-mail com anexo suspeito para caixa de e-mails de um usuário. O usuário acabou interagindo com o link

## Conteúdo do e-mail
<img width="446" height="394" alt="image" src="https://github.com/user-attachments/assets/1ca69fd4-0610-4dd5-b026-32cc6760931e" />
<img width="122" height="61" alt="image" src="https://github.com/user-attachments/assets/a5b4b21b-61e7-407e-99a9-e0f8988a27de" />



## Análise inicial 
- Ao verificar o e-mail, percebe-se que o conteúdo é propositalmente apelativo para fazer com que o usuário não pense muito antes de clicar
- Essa técnica é comum em ataques de engenharia social, onde se usa da urgência e do medo de ficar sem algo, para convencer a vítima
- Além disso, havia um anexo suspeito com nome de "free-coffee.zip", no qual a vítima executou

## Pós execução do phishing
- Ao analisar a máquina do usuário, observa-se que alguns comandos suspeitos foram executados via CMD, como:
    - net user
    - ipconfig
    - tasklist
    - systeminfo
    - route print
    - wmic logicaldisk get caption,description,providername
 
- Comandos que indicam atividades de reconhecimento dos sistema infectado, como: rotas de rede, informações de disco, de rede, de sistema e outros
- Aqui o invasor estava na fase de "discovery" pós comprometimento
- Esse tipo de atividade normalmente é utilizada para: mapear o ambiente, encontrar outros alvos e se movimentar lateralmente na rede

## Conclusão
- True Positive

## Impacto
- Informações importantes do sistema
- Possibilidade de escalonamento de privilégios
- Comprometimento do computador do usuário

# Playbook

### Contenção
- Isolar a máquina comprometida  
- Bloquear remetente e domínio do e-mail

## Erradicação
- Remover arquivos maliciosos
- Observar se tem reincidência

## Recuperação
- Redefinir credenciais do usuário  
- Validar integridade do sistema  

## Monitoramento
- Monitorar execução de comandos de reconhecimento  
- Criar alertas para comportamento suspeito em CMD  
- Buscar atividades semelhantes em outros computadores 
