# Capítulo 2: Persistência — Criação de Conta Administrativa

Com o canal C2 estabelecido, o próximo passo natural do atacante é garantir persistência no host comprometido — ou seja, manter acesso mesmo que a exploração inicial seja detectada e corrigida.

## Investigação

### 1. Identificação da criação de usuário

```spl
host="FYODOR-L" EventCode=4720
```

`EventCode 4720` é o evento de auditoria do Windows para criação de conta de usuário local.

**Resultado:** 1 evento — usuário criado: `svcvnc`.

### 2. Obtenção da senha usada na criação

```spl
host="FYODOR-L" svcvnc "password*"
```

O `Process Command Line` do evento revela o comando completo:

```
C:\Windows\system32\net1 user /add svcvnc Password123!
```

**Senha:** `Password123!`

### 3. Grupos aos quais o usuário foi adicionado

```spl
host="FYODOR-L" svcvnc EventCode=4732
```

`EventCode 4732` é o evento de auditoria para adição de membro a um grupo local.

**Resultado:** 2 eventos, em horários próximos — o usuário foi adicionado a `Users` e `Administrators`.

## Conclusão

O atacante criou uma conta local (`svcvnc`) com senha fraca e previsível (`Password123!`), adicionando-a tanto ao grupo `Users` (para não destoar em uma listagem rápida de contas) quanto ao grupo `Administrators` (garantindo acesso privilegiado total). Essa é uma técnica clássica de persistência: mesmo que o vetor de comprometimento inicial seja identificado e corrigido, o atacante mantém uma porta de entrada própria com privilégios administrativos.

## Mapeamento MITRE ATT&CK (Capítulo 2)

| Técnica | ID | Descrição |
|---|---|---|
| Create Account: Local Account | T1136.001 | Criação da conta `svcvnc` |
| Account Manipulation | T1098 | Adição da conta aos grupos `Users` e `Administrators` |
| Valid Accounts: Local Accounts | T1078.003 | Uso da conta criada para manter acesso persistente |

---

## Capítulo 2 — Persistência: criação de conta administrativa

Com o canal C2 estabelecido, o próximo objetivo natural do atacante é garantir acesso contínuo ao host, mesmo que a exploração inicial seja detectada e corrigida.

### 1. Identificando criação de usuário

```spl
host="FYODOR-L" EventCode=4720
```

`EventCode 4720` é o evento de auditoria do Windows para criação de conta local.

**Resultado:** usuário `svcvnc` criado.

### 2. Levantando credenciais e permissões

```spl
host="FYODOR-L" svcvnc
```

Na `Process Command Line` do evento de criação:

```
C:\Windows\system32\net1 user /add svcvnc Password123!
```

**Senha do usuário criado:** `Password123!`

### 3. Confirmando grupos atribuídos

```spl
host="FYODOR-L" svcvnc EventCode=4732
```

`EventCode 4732` é o evento de auditoria para "membro adicionado a grupo local" — mais preciso do que buscar por termos livres.

**Resultado:** 2 eventos, em horários próximos, mostrando o usuário `svcvnc` adicionado a:
- `Users`
- `Administrators`

### Conclusão do capítulo

O atacante criou uma conta local (`svcvnc`) com credencial própria e a incluiu tanto no grupo `Users` (reduzindo a chance de destoar numa listagem rápida de contas) quanto no grupo `Administrators` (garantindo controle total do host). Essa é uma técnica clássica de persistência: mesmo que a vulnerabilidade inicial explorada seja corrigida, o atacante mantém acesso via essa conta.

### Mapeamento MITRE ATT&CK (Capítulo 2)

| Técnica | ID | Descrição |
|---|---|---|
| Create Account: Local Account | T1136.001 | Criação da conta `svcvnc` |
| Account Manipulation | T1098 | Inclusão nos grupos `Users` e `Administrators` |

## Resposta ao Incidente (ações recomendadas)

- Isolar o host FYODOR-L da rede (Caso não tenha sido feito)
- Desabilitar/remover a conta svcvnc
- Rotacionar credenciais de contas administrativas no domínio (a senha fraca sugere reuso possível)
