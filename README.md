# Port Scanner Avançado

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Issues](https://img.shields.io/github/issues/seu-usuario/port-scanner-avancado)](https://github.com/seu-usuario/port-scanner-avancado/issues)

Um **scanner de portas TCP e UDP avançado** com interface gráfica em Python. Permite escanear IPs individuais, ranges ou CIDR, suporta filtro de resultados, barra de progresso, exportação CSV/JSON e múltiplas threads para alta performance.

---

## 🔹 Recursos

- Escaneamento TCP e UDP.
- Suporte a IP único, range de IPs ou CIDR (/24 máximo).
- Portas específicas ou intervalos de portas.
- Filtro de resultados por status:
  - `Aberta`
  - `Fechada`
  - `Filtrada`
  - `Aberta|Filtrada`
  - `Inacessível`
  - `Erro`
- Exportação de resultados para CSV e JSON.
- Threads configuráveis automaticamente para melhor desempenho.
- Interface gráfica moderna com Tkinter.

---

## 🔹 Tecnologias e Bibliotecas

- Python 3.8+  
- Tkinter (GUI)  
- socket (rede)  
- ipaddress (validação de IPs e CIDR)  
- threading e queue (execução paralela)  
- select, errno (detecção de respostas UDP)  
- csv, json (exportação de resultados)

> Observação: Tkinter já vem instalado em muitas distribuições Python. Caso falte, veja instruções abaixo.

---

## 🔹 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/port-scanner-avancado.git
cd port-scanner-avancado
```

### 2. Instale dependências

**Linux (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install python3-tk
```

**Windows:**  
Tkinter geralmente já vem instalado com Python. Certifique-se de ter **Python 3.8+**.

---

## 🔹 Uso

### Linux e Windows

1. Abra o terminal ou prompt de comando.
2. Navegue até a pasta do projeto.
3. Execute o script:

```bash
python3 port_scanner.py   # Linux / macOS
python port_scanner.py    # Windows
```

4. A interface gráfica será aberta.

---

### Configuração de Escaneamento

1. **IP**: insira um endereço IP, intervalo (`192.168.1.10-192.168.1.50`) ou CIDR (`192.168.1.0/24`).  
2. **Tipo de Escaneamento**: TCP ou UDP.  
3. **Porta específica** (opcional): se preenchido, ignora o range de portas.  
4. **Porta Inicial/Final**: define o intervalo de portas.  
5. Clique em **Iniciar Escaneamento**.  
6. Use **Parar Escaneamento** para interromper.  
7. Filtro por status na lista suspensa para visualizar apenas portas desejadas.  
8. Exportação de resultados com **Exportar CSV** ou **Exportar JSON**.

---

## 🔹 Como funciona

1. O scanner valida os IPs e portas fornecidos.  
2. Cria uma fila de tarefas com cada IP e porta a serem escaneados.  
3. Cria múltiplas threads que executam `scan_tcp_port` ou `scan_udp_port`.  
4. Atualiza a interface em tempo real, mostrando status e progresso.  
5. Permite exportar resultados completos ou filtrados para análise posterior.

**Status das portas:**

- `Aberta`: porta TCP/UDP respondendo.  
- `Fechada`: porta TCP fechada (conexão recusada).  
- `Filtrada`: porta TCP sem resposta ou bloqueada por firewall.  
- `Aberta|Filtrada`: porta UDP sem resposta clara, pode estar aberta ou filtrada.  
- `Inacessível`: host ou rede não acessível.  
- `Erro`: erro ao tentar escanear.

---

## ⚠️ Observações

- Escaneamento UDP pode variar dependendo do sistema operacional e firewalls.
- Para redes grandes, recomenda-se limitar o CIDR a `/24` para evitar lentidão.
- Utilize apenas em redes autorizadas; escaneamento sem permissão é considerado invasão.


