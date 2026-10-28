# NetWatch — Monitoramento de Rede Local

  O **NetWatch** é uma aplicação desktop desenvolvida em Python para descoberta, monitoramento e análise de dispositivos conectados a uma rede local.
O projeto oferece recursos de inventário de dispositivos, identificação de fabricantes, análise inicial de portas TCP e registro de eventos para facilitar a observação da atividade da rede.

A aplicação foi desenvolvida com foco em organização das informações, persistência local dos dados e identificação de alterações entre varreduras.

## Funcionalidades

- **Descoberta de dispositivos:** identifica dispositivos encontrados na rede local e reúne informações como endereço IP, endereço MAC e nome do dispositivo, quando disponíveis.
- **Inventário inteligente:** mantém um histórico de observações e registra a frequência com que os dispositivos são encontrados.
- **Classificação de dispositivos:** utiliza informações disponíveis para sugerir categorias de dispositivos, como computadores, celulares, impressoras, roteadores e equipamentos IoT.
- **Identificação de fabricantes:** utiliza informações fornecidas pela ferramenta de descoberta e uma base local de prefixos OUI quando disponível.
- **Lista de dispositivos confiáveis:** permite manter uma referência local dos dispositivos reconhecidos pelo usuário.
- **Detecção de alterações:** compara varreduras para registrar novos dispositivos, mudanças de endereço MAC e dispositivos que não foram detectados em uma verificação posterior.
- **Análise inicial de portas TCP:** permite analisar portas selecionadas de um dispositivo escolhido.
- **Registro de eventos:** armazena informações sobre as verificações e alterações observadas.
- **Interface gráfica:** disponibiliza os recursos por meio de uma aplicação desktop construída com Tkinter.
- **Persistência local:** utiliza arquivos CSV para manter o inventário, as configurações de confiança e os registros entre execuções.

## Tecnologias utilizadas

- **Python 3** — linguagem principal.
- **Tkinter / ttk** — interface gráfica.
- **Nmap** — ferramenta utilizada na descoberta de dispositivos e na obtenção de informações da rede.
- **Linux e utilitários de rede** — detecção da interface ativa, identificação da sub-rede e consulta de vizinhos.
- **CSV** — armazenamento local dos dados e históricos.
- **Git e GitHub** — versionamento e publicação do projeto.

## Requisitos

Antes de executar o projeto, verifique se o ambiente possui:

- Linux com suporte aos utilitários de rede utilizados pela aplicação.
- Python 3.
- Tkinter.
- Nmap.
- Git, caso queira clonar o repositório.

## Instalação no Linux Mint / Ubuntu

### 1. Instale os requisitos

Abra o terminal e execute:

```bash
sudo apt update
sudo apt install python3 python3-tk nmap iproute2 git
```

### 2. Clone o repositório

```bash
git clone https://github.com/GuidoLobo/NetWatch.git
```

### 3. Entre na pasta do projeto

```bash
cd NetWatch
```

### 4. Execute a aplicação

```bash
python3 main.py
```

A interface gráfica será aberta se o ambiente tiver suporte à exibição de janelas.

## Como utilizar

1. Inicie a aplicação.
2. Execute a descoberta de dispositivos da rede local.
3. Consulte as informações dos dispositivos encontrados.
4. Revise os dispositivos desconhecidos e confirme quais são legítimos antes de adicioná-los à lista de confiáveis.
5. Se necessário, selecione um dispositivo e execute a análise inicial de portas TCP.
6. Consulte os eventos e os registros locais para acompanhar as alterações entre as verificações.

Os nomes, fabricantes e tipos de dispositivos são identificações prováveis baseadas nas informações disponíveis e não devem ser tratados como certezas absolutas.

## Armazenamento dos dados

Durante a execução, a aplicação utiliza a pasta `logs/` para manter arquivos locais de inventário, histórico, eventos, dispositivos confiáveis e outras informações auxiliares.

Esses arquivos podem conter endereços IP, endereços MAC e outros dados específicos da rede monitorada. Por esse motivo, os registros locais são excluídos do versionamento pelo `.gitignore`.

**Recomendação:** não publique logs reais da sua rede. Para compartilhar exemplos, utilize dados fictícios ou anonimizados.

## Segurança e limitações

- Utilize o NetWatch somente em redes próprias ou em redes para as quais você tenha autorização explícita para realizar verificações.
- Um dispositivo desconhecido não é necessariamente malicioso.
- Um dispositivo que não aparece em uma varredura pode estar desligado, inativo ou temporariamente indisponível.
- Uma mudança de endereço MAC pode ter causas legítimas, como o uso de endereços aleatórios por dispositivos móveis.
- A análise de portas é inicial e limitada às portas configuradas na aplicação. Ela não substitui uma auditoria de segurança completa.
- A identificação de fabricantes e categorias depende das informações disponíveis e pode ser inconclusiva.

O NetWatch é uma ferramenta de observação e apoio à análise de redes locais, não um sistema de detecção de intrusão certificado.

## Objetivos do projeto

Este projeto tem como objetivos praticar e aplicar conhecimentos de:

- Programação em Python.
- Desenvolvimento de interfaces gráficas.
- Redes de computadores e endereçamento IP.
- Automação de verificações de rede.
- Organização e persistência de dados.
- Controle de versão com Git.
- Boas práticas de segurança e tratamento responsável de informações.

## Autor

**Guilherme Lobo**

GitHub: [@GuidoLobo](https://github.com/GuidoLobo)

## Licença

Nenhuma licença foi especificada neste repositório até o momento. Os termos de uso e redistribuição deverão ser definidos pelo autor caso o projeto seja disponibilizado sob uma licença de código aberto.
