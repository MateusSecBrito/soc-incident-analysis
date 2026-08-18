# Investigação: Comunicação C2 via PowerShell Ofuscado — Host FYODOR-L

**Dataset:** Splunk BOTSv3 (cenário Frothly / grupo Taedonggang)
**Host comprometido:** FYODOR-L.froth.ly

## Objetivo

Identificar como o atacante estabeleceu comunicação com sua infraestrutura de Comando e Controle (C2) após comprometer o host `FYODOR-L`, e mapear o endpoint (URL) mais utilizado nessa comunicação.

## Hipótese inicial

Atacantes, normalmente, utilizam PowerShell para se comunicar com o servidor C2, muitas vezes escondendo os comandos em Base64 para tentar escapar de detecções. 

## Investigação

### 1. Busca inicial por indício de ofuscação

<img width="281" height="71" alt="image" src="https://github.com/user-attachments/assets/1f0bc98e-9bb3-4c11-a1bb-044984b2698d" />

**Resultado:** 22 eventos.

FromBase64 é um método de decodificação bastante utilizado por atacantes.<br> 
A ordem de eventos costuma funcionar assim: <br>
1 - O atacante cria um código malicioso e o codifica com base64 para tentar passar despercebido<br>
2 - O código chega ao dispositivo da vítima<br>
3 - Um script decodifica o código utilizando FromBase64<br>
4 - O código é executado<br>


### 2. Identificação do sourcetype relevante

<img width="370" height="74" alt="image" src="https://github.com/user-attachments/assets/2c780671-3be6-49b8-a66d-1df99c99e267" />



| sourcetype | count |
|---|---|
| wineventlog:microsoft-windows-powershell/operational | 6 |
| wineventlog:security | 2 |
| winhostmon | 10 |
| xmlwineventlog:microsoft-windows-sysmon/operational | 4 |

O log específico do PowerShell (`WinEventLog:Microsoft-Windows-PowerShell/Operational`) é o mais importante nesse caso, pois registra o comando completo executado.

### 3. Análise do comando decodificado

<img width="630" height="99" alt="image" src="https://github.com/user-attachments/assets/2f6bbf29-282e-44cc-8715-c48bed049e6a" />

**Resultado:** 6 eventos. <br>

Um dos 6 eventos revela o mecanismo de execução:

```powershell
IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))
```

**Leitura do comando (de dentro para fora):**
1. `gp HKLM:\Software\Microsoft\Network debug`: lê o valor `debug` de uma chave do registro do Windows.
2. `[Convert]::FromBase64String(...)`: decodifica esse valor de Base64 para bytes.
3. `[Text.Encoding]::UNICODE.GetString(...)`: converte os bytes em texto legível (script PowerShell real).
4. `IEX` (`Invoke-Expression`):  executa esse texto como código.

Então, basicamente, o atacante escondeu um payload no registro do windows em vez de um arquivo em disco, dificultando ainda mais a detecção. Essa técnica é conhecida como **fileless** (execução sem arquivo).

Dos outros eventos, foram decodificados dois canais distintos usados pelo atacante:

- `https://45.77.53.176:443` — canal de conexão inicial (HTTPS).
- Três caminhos HTTP no mesmo servidor: **/admin/get.php**, **/news.php**, **/login/process.php**.

### 4. Determinando o endpoint C2 principal

A contagem dentro dos 6 eventos filtrados por FromBase64String mostrou um empate entre **/admin/get.php** e **/news.php** (Cada um acessado duas vezes). Porém, esse filtro só captura o momento em que o comando ainda estava decodificado, o endpoint ainda foi contatado outras vezes durante o ataque.

Removendo a restrição de `FromBase64String` e buscando diretamente pelas URLs:

<img width="631" height="95" alt="image" src="https://github.com/user-attachments/assets/5f66d1fa-be48-4a70-9e28-19ba647d5526" />


**Resultado:** `/admin/get.php` aparece em 5 execuções distintas, no intervalo de 1h30 (10:01–11:32), bem mais frequente que os outros dois, isso confirma o caminho como c2 principal.

## Conclusão

O atacante estabeleceu comunicação com o servidor `45.77.53.176`, combinando:
- uma conexão inicial via **HTTPS (porta 443)**;
- comunicação operacional contínua via **HTTP**, acessando repetidamente o endpoint `/admin/get.php` ao longo de aproximadamente 1h30 (10:01–11:32).

O comando de execução foi mantido oculto, utilzando a técnica de fileless, dentro do registro do Windows, decodificado e executado em memória via PowerShell 

## Mapeamento MITRE ATT&CK

| Técnica | ID | Descrição |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Uso de PowerShell para executar o payload |
| Obfuscated Files or Information | T1027 | Payload codificado em Base64 |
| Modify Registry | T1112 | Payload armazenado em chave do registro do Windows |
| Application Layer Protocol: Web Protocols | T1071.001 | Comunicação C2 via HTTP/HTTPS |

## Lição de investigação

Filtrar por um termo técnico específico (como `FromBase64String`) é eficaz para localizar o primeiro indício de um comportamento malicioso, mas pode limitar a visão do quadro completo. Uma vez identificado o padrão (URL, IP, processo), o passo seguinte é remover esse filtro e buscar diretamente pela evidência (a URL, neste caso) em toda a janela de tempo relevante — revelando o verdadeiro volume e a real frequência da atividade.

---

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
