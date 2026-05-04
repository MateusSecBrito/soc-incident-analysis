# Execução de Script PowerShell Malicioso

# Situação: Foi detectado a execução de um script suspeito em um host da rede interna de uma empresa, seguida de uma comunição com host externo

# Alerta inicial
- Host: 172.16.17.206  
- Hostname: Tony  
- Fonte da detecção: EDR  
- Caminho do arquivo:  
  `C:\Users\LetsDefend\Downloads\payload_1.ps1`  
- Hash do arquivo:  
  `db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0`
- URL de origem:  
  `https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1`
  

# Script Executado: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\LetsDefend\Downloads\payload_1.ps1\payload_1.ps1'"
  -> Comportamento suspeito com a execução do "ExecutionPolicy -Scope Process Bypass", tentando burlar mecanismos de segurança
  -> Execução de um arquivo .ps1, diretamente na pasta de downloads 

# Log Firewall
- Origem: 172.16.17.206
- Destino: 161.22.46.148
- Porta: 443 (HTTPS)
- Processo: powershell.exe
- Status: SUCCESS
  -> Uma comunicação externa foi iniciada logo após a execução do script, utilizando powershell e https. Forte indício de comunicação com servidor C2, podendo utilizado para controle remoto da máquina ou como backdoor 

# Conclusão
-> True Positive: O usuário executou o arquivo em seu computador, causando a execução de um script suspeito no powershell que iniciou a conexão com um cliente exerto, porssivelmente um servidor C2, indicando comprometimento da máquina

# Impacto 
-> Risco de exfiltração de dados
-> Possível controle remoto da máquina
-> Possibilidade de movimentação lateral na rede

# Playbook
-> Contenção
- Isolar o host do resto da rede
- Bloquear IP externo (161.22.46.148)

-> Erradicação
- Remover script malicioso
- Encerrar os processos no powershell

-> Recuperação
- Redefinir credenciais do usuário

-> Monitoramento
- Criar alertas para scripts semelhantes 
- Buscar indicadores de compromentimento em outras máquinas


