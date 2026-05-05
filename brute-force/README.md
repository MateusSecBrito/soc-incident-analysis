# Situação: Foram identificadas múltiplas tentativas de login falhas a partir de um único endereço IP externo, utilizando diferentes contas inexistentes, com tentativas de acesso remoto via RDP.

# Alerta Inicial 
- IP de Origem: 218.92.0.56 
- Host de destino: 172.16.17.148  
- Serviço: RDP (porta 3389)

# Análise

-> O ip de origem é classificado como "malicioso" em plataformas de threat intel
-> As tentativas de login foram feitas em diferentes contas, como: guest e admin

# Log de sistema
- EventID: 4625 (Falha de logon)  
- Motivo: Nome de usuário inválido ou senha incorreta

# Análise 
- Tentativa falha de login, provavelmente feito com intuito de descobrir credenciais válidas

# Log do Firewall
- Origem: 218.92.0.56  
- Destino: 172.16.17.148  
- Porta: 3389 (RDP)  
- Status: Permitido

# Análise
-> "Status: Permitido" mostra que o firewall permitiu a conxeão com a máquina, porém o invasor não passou da fase de logon


# Análise final
-> O comportamento apresentado é compatível com o padrão de ataques de força bruta, onde o invasor tenta diversas combinações de usuários e senhas

# Conclusão
-> True Positive

# Impacto
-> Comprometimento da conta
-> Possível acesso não autorizado

# Playbook

-> Contenção 
-  Bloquear o Ip de origem
-  Restringir o acesso RDP externo

-> Erradicação
-  Revisar outras tentativas de login suspeitas para ver se ouve algum sucesso
  
-> Recuperação
-  Redefinir as senhas de contas importantes
-  Aplicar políticas de senhas fortes
  
-> Monitoramento
- Criar alertas para falhas de login contínuas
- Monitorar os acessos RDP
- Implementar bloqueio por tentativas falhas









