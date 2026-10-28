import csv
import hashlib
import ipaddress
import queue
import re
import socket
import subprocess
import threading
import tkinter as tk

from datetime import datetime
from pathlib import Path
from tkinter import ttk, messagebox


REDE_LOCAL = None  # Detectada automaticamente a partir da rota padrão do sistema.

# Portas TCP comuns para uma análise inicial da rede local.
PORTAS_ANALISAR = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
    554, 631, 993, 995, 1883, 3306, 3389, 5000, 5432,
    5900, 8000, 8080, 8443, 9100, 27036
]

PASTA_LOGS = Path(__file__).parent / "logs"
ARQUIVO_LOG = PASTA_LOGS / "verificacoes.csv"
ARQUIVO_CONFIAVEIS = PASTA_LOGS / "dispositivos_conhecidos.csv"
ARQUIVO_HISTORICO = PASTA_LOGS / "historico_dispositivos.csv"
ARQUIVO_ESTADO = PASTA_LOGS / "estado_anterior_dispositivos.csv"
ARQUIVO_EVENTOS = PASTA_LOGS / "eventos_rede.csv"
ARQUIVO_REVISAO_ALERTAS = PASTA_LOGS / "revisao_alertas.csv"
ARQUIVO_INVENTARIO = PASTA_LOGS / "inventario_inteligente.csv"
ARQUIVO_NOMES_PERSONALIZADOS = PASTA_LOGS / "nomes_personalizados.csv"
ARQUIVO_OUI = PASTA_LOGS / "oui.csv"  # CSV opcional com prefixos MAC e fabricantes.

# A confiança é armazenada localmente. MAC é preferido; IP é usado quando
# o MAC não está disponível, com menor confiabilidade.
dispositivos_atuais = {}
dispositivos_conhecidos = {}
dispositivos_ultima_varredura = {}
inventario_inteligente = {}
nomes_personalizados = {}  # MAC preferencial; IP apenas quando o MAC não está disponível.
revisoes_alertas = {}  # ID do evento -> status de revisão persistente.

fila_resultados = queue.Queue()

# Base embarcada pequena e conservadora. Para maior cobertura, coloque um CSV
# de OUI em logs/oui.csv (colunas aceitas: MAC Prefix/Vendor, oui/manufacturer,
# prefixo/fabricante ou endereço MAC/organização). O CSV é lido localmente.
BASE_OUI_LOCAL = {
    "84:0B:BB": "MitraStar Technology",
    "D8:36:5F": "Intelbras",
    "1C:1A:1B": "Shanghai Sunmi Technology",
}


def normalizar_prefixo_oui(valor):
    """Converte prefixos OUI em formato AA:BB:CC, aceitando hífens e pontos."""
    hexadecimal = re.sub(r"[^0-9A-Fa-f]", "", (valor or "")).upper()
    if len(hexadecimal) < 6 or not re.fullmatch(r"[0-9A-F]{6,12}", hexadecimal):
        return ""
    return ":".join(hexadecimal[i:i + 2] for i in range(0, 6, 2))


def carregar_base_oui():
    """Mescla um CSV local opcional à base embarcada sem acesso à internet."""
    if not ARQUIVO_OUI.exists():
        return
    try:
        with open(ARQUIVO_OUI, newline="", encoding="utf-8-sig") as arquivo:
            leitor = csv.DictReader(arquivo)
            if not leitor.fieldnames:
                print("Base OUI ignorada: o CSV não possui cabeçalho.")
                return
            campos = {re.sub(r"[^a-z]", "", c.lower()): c for c in leitor.fieldnames}
            campo_prefixo = next((campos[k] for k in ("macprefix", "oui", "prefixo", "macaddress", "assignment") if k in campos), None)
            campo_fabricante = next((campos[k] for k in ("vendor", "manufacturer", "fabricante", "organization", "organizationname", "empresa") if k in campos), None)
            if not campo_prefixo or not campo_fabricante:
                print("Base OUI ignorada: use colunas de prefixo MAC e fabricante/organização.")
                return
            carregados = 0
            for linha in leitor:
                prefixo = normalizar_prefixo_oui(linha.get(campo_prefixo, ""))
                fabricante = (linha.get(campo_fabricante) or "").strip()
                if prefixo and fabricante:
                    BASE_OUI_LOCAL[prefixo] = fabricante
                    carregados += 1
            print(f"Base OUI local: {carregados} prefixo(s) carregado(s) de {ARQUIVO_OUI.name}.")
    except (OSError, csv.Error) as erro:
        print(f"Não foi possível carregar a base OUI opcional: {erro}")



def chave_dispositivo(ip, mac):
    """Prefere o MAC; usa IP quando o MAC não está disponível."""
    return (mac or ip or "").strip().upper()


def carregar_nomes_personalizados():
    """Carrega os apelidos escolhidos pelo usuário, separados do hostname original."""
    nomes_personalizados.clear()
    if not ARQUIVO_NOMES_PERSONALIZADOS.exists():
        return
    try:
        with open(ARQUIVO_NOMES_PERSONALIZADOS, newline="", encoding="utf-8") as arquivo:
            for linha in csv.DictReader(arquivo):
                mac = (linha.get("MAC") or "").strip().upper()
                ip = (linha.get("IP") or "").strip()
                nome = (linha.get("Nome personalizado") or "").strip()
                chave = mac or ip
                if chave and nome:
                    nomes_personalizados[chave] = {"ip": ip, "mac": mac, "nome": nome}
    except (OSError, csv.Error) as erro:
        print(f"Não foi possível carregar os nomes personalizados: {erro}")


def salvar_nomes_personalizados():
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    temporario = ARQUIVO_NOMES_PERSONALIZADOS.with_suffix(".tmp")
    with open(temporario, "w", newline="", encoding="utf-8") as arquivo:
        campos = ["IP", "MAC", "Nome personalizado"]
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for item in nomes_personalizados.values():
            escritor.writerow({"IP": item.get("ip", ""), "MAC": item.get("mac", ""),
                               "Nome personalizado": item.get("nome", "")})
    temporario.replace(ARQUIVO_NOMES_PERSONALIZADOS)


def obter_nome_personalizado(ip, mac):
    """Busca por MAC primeiro; usa IP somente se o MAC não estiver disponível."""
    mac = (mac or "").strip().upper()
    if mac and mac in nomes_personalizados:
        return nomes_personalizados[mac].get("nome", "")
    if not mac and ip in nomes_personalizados:
        return nomes_personalizados[ip].get("nome", "")
    return ""


def carregar_inventario_inteligente():
    """Carrega metadados persistentes sem alterar a lista de confiança."""
    inventario_inteligente.clear()
    if not ARQUIVO_INVENTARIO.exists():
        return
    try:
        with open(ARQUIVO_INVENTARIO, newline="", encoding="utf-8") as arquivo:
            for linha in csv.DictReader(arquivo):
                ip = (linha.get("IP") or "").strip()
                mac = (linha.get("MAC") or "").strip().upper()
                chave = chave_dispositivo(ip, mac)
                if chave:
                    try:
                        aparicoes = int(linha.get("Aparições") or 0)
                    except ValueError:
                        aparicoes = 0
                    inventario_inteligente[chave] = {
                        "ip": ip, "mac": mac,
                        "nome": (linha.get("Nome") or ip).strip(),
                        "nome_personalizado": (linha.get("Nome personalizado") or "").strip(),
                        "fabricante": (linha.get("Fabricante provável") or "Desconhecido").strip(),
                        "tipo": (linha.get("Tipo provável") or "Não identificado").strip(),
                        "primeira_observacao": (linha.get("Primeira observação") or "").strip(),
                        "ultima_observacao": (linha.get("Última observação") or "").strip(),
                        "aparicoes": aparicoes,
                    }
    except (OSError, csv.Error) as erro:
        print(f"Não foi possível carregar o inventário inteligente: {erro}")


def salvar_inventario_inteligente():
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    temporario = ARQUIVO_INVENTARIO.with_suffix(".tmp")
    campos = ["IP", "MAC", "Tipo de MAC", "Nome", "Nome personalizado", "Fabricante provável", "Tipo provável",
              "Primeira observação", "Última observação", "Aparições"]
    with open(temporario, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for item in inventario_inteligente.values():
            escritor.writerow({
                "IP": item.get("ip", ""), "MAC": item.get("mac", ""),
                "Tipo de MAC": item.get("tipo_mac", classificar_tipo_mac(item.get("mac", ""))),
                "Nome": item.get("nome", ""),
                "Nome personalizado": item.get("nome_personalizado", obter_nome_personalizado(item.get("ip", ""), item.get("mac", ""))),
                "Fabricante provável": item.get("fabricante", "Desconhecido"),
                "Tipo provável": item.get("tipo", "Não identificado"),
                "Primeira observação": item.get("primeira_observacao", ""),
                "Última observação": item.get("ultima_observacao", ""),
                "Aparições": item.get("aparicoes", 0),
            })
    temporario.replace(ARQUIVO_INVENTARIO)


def classificar_tipo_mac(mac):
    """Classifica o bit U/L do primeiro octeto; não determina se há spoofing."""
    mac = (mac or "").strip().upper()
    if not mac or mac in ("NÃO IDENTIFICADO", "NAO IDENTIFICADO"):
        return "Indisponível"
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return "Inválido / não reconhecido"
    primeiro_octeto = int(mac[:2], 16)
    if primeiro_octeto & 0x01:
        return "Multicast (inesperado para host)"
    if primeiro_octeto & 0x02:
        return "Local/privado (OUI não confiável)"
    return "Globalmente atribuído"


def consultar_fabricante_local(mac):
    """Consulta a base OUI local; MAC aleatório/local não serve para inferir fabricante."""
    mac = (mac or "").strip().upper().replace("-", ":")
    if classificar_tipo_mac(mac) != "Globalmente atribuído":
        return "Desconhecido"
    prefixo = normalizar_prefixo_oui(mac)
    return BASE_OUI_LOCAL.get(prefixo, "Desconhecido")


def resolver_fabricante(mac, fabricante_nmap):
    """Prioriza fabricante informado pelo Nmap; usa a base local como fallback."""
    tipo_mac = classificar_tipo_mac(mac)
    if tipo_mac != "Globalmente atribuído":
        return "Não confiável pelo prefixo" if tipo_mac == "Local/privado (OUI não confiável)" else "Desconhecido"
    if fabricante_nmap and fabricante_nmap.strip().lower() not in ("desconhecido", "unknown"):
        return fabricante_nmap.strip()
    return consultar_fabricante_local(mac)


def fabricante_confiavel_para_mac(mac, fabricante):
    """Não atribui fabricante por prefixo quando o MAC é administrado localmente."""
    tipo_mac = classificar_tipo_mac(mac)
    if tipo_mac == "Local/privado (OUI não confiável)":
        return "Não confiável pelo prefixo"
    return fabricante or "Desconhecido"


def inferir_tipo_dispositivo(nome, fabricante, nome_personalizado=""):
    """Classifica por indícios textuais; nunca trata a hipótese como certeza."""
    texto = f"{nome or ''} {nome_personalizado or ''} {fabricante or ''}".lower()
    regras = [
        (("gateway", "router", "roteador", "mitrastar", "tp-link", "tplink", "zyxel", "huawei", "h3621", "mikrotik", "ubiquiti", "unifi", "access point", "wireless ap"), "Roteador / ponto de acesso"),
        (("galaxy", "samsung", "iphone", "ipad", "android", "pixel", "xiaomi", "redmi", "motorola", "oneplus", "celular", "smartphone", "tablet", "realme", "oppo", "vivo mobile"), "Possível celular/tablet"),
        (("intelbras", "mhdx", "hikvision", "dahua", "nvr", "dvr", "camera", "câmera", "ipcam", "webcam", "reolink", "ezviz"), "Possível câmera/gravador"),
        (("printer", "impressora", "brother", "epson", "canon", "laserjet", "deskjet", "officejet", "pixma", "print server", "ricoh", "kyocera", "lexmark"), "Possível impressora"),
        (("windows", "desktop", "laptop", "notebook", "macbook", "thinkpad", "dell", "lenovo", "asus pc", "acer", "workstation", "computador", "pc gamer", "gui"), "Possível computador"),
        (("sunmi", "pos terminal", "terminal de pagamento", "maquininha", "point of sale", "p.o.s."), "Possível terminal de pagamento"),
        (("raspberry", "raspberry pi", "arduino", "esp32", "esp8266", "embedded", "openwrt", "home assistant"), "Possível dispositivo embarcado/IoT"),
        (("chromecast", "google tv", "fire tv", "roku", "smart tv", "android tv", "appletv", "apple tv", "televisão", "televisao"), "Possível TV/dispositivo de mídia"),
        (("sonos", "speaker", "alto-falante", "alexa", "echo dot", "google nest", "smart speaker"), "Possível alto-falante inteligente"),
        (("nas", "synology", "qnap", "storage", "network attached storage"), "Possível servidor/NAS"),
        (("server", "servidor", "proxmox", "esxi", "vmware", "hyper-v"), "Possível servidor/virtualização"),
        (("playstation", "xbox", "nintendo", "switch console", "steam deck"), "Possível console de jogos"),
    ]
    for termos, tipo in regras:
        if any(termo in texto for termo in termos):
            return tipo
    return "Não identificado"


def atualizar_inventario_inteligente(ip, mac, nome, fabricante):
    """Atualiza presença sem aprovar automaticamente o dispositivo."""
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chave = chave_dispositivo(ip, mac)
    anterior = inventario_inteligente.get(chave, {})
    tipo_mac = classificar_tipo_mac(mac)
    fabricante_recebido = fabricante if fabricante and fabricante != "Desconhecido" else anterior.get("fabricante", "Desconhecido")
    fabricante_atual = fabricante_confiavel_para_mac(mac, fabricante_recebido)
    item = {
        "ip": ip, "mac": (mac or "").upper(), "tipo_mac": tipo_mac, "nome": nome or ip,
        "nome_personalizado": obter_nome_personalizado(ip, mac),
        "fabricante": fabricante_atual,
        "tipo": inferir_tipo_dispositivo(nome, fabricante_atual, obter_nome_personalizado(ip, mac)),
        "primeira_observacao": anterior.get("primeira_observacao") or agora,
        "ultima_observacao": agora,
        "aparicoes": int(anterior.get("aparicoes", 0)) + 1,
    }
    inventario_inteligente[chave] = item
    return item


def carregar_dispositivos_conhecidos():
    """Carrega a lista local de dispositivos aprovados pelo usuário."""
    dispositivos_conhecidos.clear()
    if not ARQUIVO_CONFIAVEIS.exists():
        return

    try:
        with open(ARQUIVO_CONFIAVEIS, newline="", encoding="utf-8") as arquivo:
            for linha in csv.DictReader(arquivo):
                mac = (linha.get("MAC") or "").strip().upper()
                ip = (linha.get("IP") or "").strip()
                chave = mac or ip
                if chave:
                    dispositivos_conhecidos[chave] = {
                        "ip": ip,
                        "mac": mac,
                        "nome": (linha.get("Nome") or "").strip(),
                        "desde": (linha.get("Confiável desde") or "").strip(),
                    }
    except (OSError, csv.Error) as erro:
        print(f"Não foi possível ler a lista de dispositivos conhecidos: {erro}")


def salvar_dispositivos_conhecidos():
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    with open(ARQUIVO_CONFIAVEIS, "w", newline="", encoding="utf-8") as arquivo:
        campos = ["IP", "MAC", "Nome", "Confiável desde"]
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for item in dispositivos_conhecidos.values():
            escritor.writerow({
                "IP": item.get("ip", ""),
                "MAC": item.get("mac", ""),
                "Nome": item.get("nome", ""),
                "Confiável desde": item.get("desde", ""),
            })


def salvar_observacao_dispositivo(ip, mac, nome, classificacao, detalhes=""):
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    existe = ARQUIVO_HISTORICO.exists() and ARQUIVO_HISTORICO.stat().st_size > 0
    with open(ARQUIVO_HISTORICO, "a", newline="", encoding="utf-8") as arquivo:
        campos = ["Data e hora", "IP", "MAC", "Nome", "Classificação", "Detalhes"]
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        if not existe:
            escritor.writeheader()
        escritor.writerow({
            "Data e hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "IP": ip,
            "MAC": mac or "Não identificado",
            "Nome": nome,
            "Classificação": classificacao,
            "Detalhes": detalhes,
        })


def carregar_estado_anterior():
    """Carrega o inventário da última varredura concluída com sucesso."""
    dispositivos_ultima_varredura.clear()
    if not ARQUIVO_ESTADO.exists():
        return
    try:
        with open(ARQUIVO_ESTADO, newline="", encoding="utf-8") as arquivo:
            for linha in csv.DictReader(arquivo):
                ip = (linha.get("IP") or "").strip()
                mac = (linha.get("MAC") or "").strip().upper()
                if ip:
                    dispositivos_ultima_varredura[mac or ip] = {
                        "ip": ip, "mac": mac,
                        "nome": (linha.get("Nome") or ip).strip(),
                    }
    except (OSError, csv.Error) as erro:
        print(f"Não foi possível carregar o inventário anterior: {erro}")


def salvar_estado_atual(dispositivos):
    """Persiste apenas o último inventário concluído com sucesso."""
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    temporario = ARQUIVO_ESTADO.with_suffix(".tmp")
    with open(temporario, "w", newline="", encoding="utf-8") as arquivo:
        campos = ["IP", "MAC", "Nome"]
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for item in dispositivos:
            escritor.writerow({"IP": item["ip"], "MAC": item["mac"], "Nome": item["nome"]})
    temporario.replace(ARQUIVO_ESTADO)


def registrar_evento(tipo, ip, mac, nome, detalhes):
    """Grava eventos observados; não conclui que um evento seja ataque."""
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    existe = ARQUIVO_EVENTOS.exists() and ARQUIVO_EVENTOS.stat().st_size > 0
    with open(ARQUIVO_EVENTOS, "a", newline="", encoding="utf-8") as arquivo:
        campos = ["Data e hora", "Evento", "IP", "MAC", "Nome", "Detalhes"]
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        if not existe:
            escritor.writeheader()
        escritor.writerow({
            "Data e hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Evento": tipo, "IP": ip, "MAC": mac or "Não identificado",
            "Nome": nome, "Detalhes": detalhes,
        })


def comparar_varreduras(dispositivos_novos):
    """Compara varreduras bem-sucedidas por MAC; usa IP quando MAC falta."""
    novos = {((d["mac"] or d["ip"]).upper()): d for d in dispositivos_novos}
    anteriores = dict(dispositivos_ultima_varredura)
    eventos = []

    for chave, item in novos.items():
        if chave not in anteriores:
            # Se o MAC é novo mas o IP já existia com outro MAC, sinaliza mudança.
            anterior_ip = next((x for x in anteriores.values() if x["ip"] == item["ip"]), None)
            if anterior_ip and anterior_ip.get("mac") and item.get("mac") and anterior_ip["mac"] != item["mac"]:
                tipo = "MAC ALTERADO NO IP"
                detalhe = f"Antes: {anterior_ip['mac']}; agora: {item['mac']}. Pode ser troca legítima, MAC aleatório ou spoofing; investigar."
            elif anteriores:
                tipo = "NOVO DISPOSITIVO"
                detalhe = "Não apareceu na última varredura bem-sucedida; confirmar no roteador."
            else:
                tipo = "PRIMEIRA OBSERVAÇÃO"
                detalhe = "Inventário inicial; ainda não há comparação anterior."
            eventos.append((tipo, item, detalhe))

    if anteriores:
        chaves_atuais = set(novos)
        for chave, item in anteriores.items():
            if chave not in chaves_atuais:
                # Só reporta ausência como observação; pode estar dormindo/desconectado.
                eventos.append(("NÃO DETECTADO NESTA VARREDURA", item,
                                "Estava na varredura anterior, mas não respondeu agora. Isso não prova que saiu da rede."))

    for tipo, item, detalhe in eventos:
        registrar_evento(tipo, item["ip"], item.get("mac", ""), item.get("nome", ""), detalhe)
    salvar_estado_atual(dispositivos_novos)
    dispositivos_ultima_varredura.clear()
    dispositivos_ultima_varredura.update(novos)
    return eventos


def obter_rede_local():
    """Detecta a sub-rede IPv4 da interface usada pela rota padrão."""
    try:
        rota = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5, check=False
        )
        if rota.returncode != 0 or not rota.stdout.strip():
            raise RuntimeError("Não foi possível encontrar a rota padrão IPv4.")

        partes_rota = rota.stdout.splitlines()[0].split()
        if "dev" not in partes_rota:
            raise RuntimeError("A rota padrão não informa uma interface de rede.")
        interface = partes_rota[partes_rota.index("dev") + 1]

        enderecos = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"],
            capture_output=True, text=True, timeout=5, check=False
        )
        if enderecos.returncode != 0:
            raise RuntimeError("Não foi possível consultar o IP da interface ativa.")

        for linha in enderecos.stdout.splitlines():
            correspondencia = re.search(r"\binet\s+(\d+(?:\.\d+){3}/\d+)\b", linha)
            if correspondencia:
                rede = ipaddress.ip_interface(correspondencia.group(1)).network
                if not isinstance(rede, ipaddress.IPv4Network):
                    continue
                # Evita varreduras acidentais de redes muito grandes.
                if rede.num_addresses > 4096:
                    raise RuntimeError(
                        f"A rede detectada ({rede}) é grande demais para a descoberta automática."
                    )
                return str(rede), interface

        raise RuntimeError(f"Nenhum endereço IPv4 global encontrado na interface {interface}.")
    except (OSError, subprocess.TimeoutExpired, ValueError) as erro:
        raise RuntimeError(f"Falha ao detectar a rede local: {erro}") from erro


def obter_macs_vizinhos():
    """Consulta a tabela de vizinhos do Linux para associar IPs a MACs."""
    macs = {}
    try:
        resultado = subprocess.run(
            ["ip", "neigh", "show"], capture_output=True, text=True,
            timeout=10, check=False
        )
        for linha in resultado.stdout.splitlines():
            partes = linha.split()
            if "lladdr" in partes:
                indice = partes.index("lladdr")
                if indice + 1 < len(partes):
                    macs[partes[0]] = partes[indice + 1].upper()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return macs


def classificar_dispositivo(ip, mac):
    """Classifica por MAC quando possível; não declara desconhecido como invasor."""
    mac = (mac or "").upper()
    chave = mac or ip
    if chave in dispositivos_conhecidos:
        if mac:
            if classificar_tipo_mac(mac) == "Local/privado (OUI não confiável)":
                return "CONHECIDO", "MAC local/privado corresponde à lista de confiança; fabricante não é inferido pelo prefixo."
            return "CONHECIDO", "MAC corresponde à lista de confiança."
        return "CONHECIDO (IP)", "MAC indisponível; correspondência baseada apenas no IP."

    for conhecido in dispositivos_conhecidos.values():
        if conhecido.get("ip") == ip and not conhecido.get("mac"):
            return "CONHECIDO (IP)", "Lista de confiança foi criada sem MAC; correspondência baseada apenas no IP."

    # Alerta se um IP previamente confiável agora aparece com outro MAC.
    if mac:
        for conhecido in dispositivos_conhecidos.values():
            if conhecido.get("ip") == ip and conhecido.get("mac") and conhecido["mac"] != mac:
                return "ALERTA: MAC ALTERADO", "O IP era associado a outro MAC na lista de confiança. Verifique antes de concluir que é uma invasão."

    if mac:
        return "DESCONHECIDO", "MAC não consta na lista de confiança; confirme se o dispositivo é legítimo."
    return "DESCONHECIDO (SEM MAC)", "Não foi possível obter o MAC; a identificação é menos confiável."


def identificar_servico(porta):
    """
    Retorna uma associação provável para a porta.
    Isso não confirma qual aplicação está realmente usando a porta remota.
    """
    servicos = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        554: "RTSP",
        631: "IPP / impressão",
        993: "IMAPS",
        995: "POP3S",
        1883: "MQTT",
        3306: "MySQL",
        3389: "RDP",
        5000: "Possível serviço web",
        5432: "PostgreSQL",
        5900: "VNC",
        8000: "Possível serviço HTTP",
        8080: "HTTP alternativo",
        8443: "HTTPS alternativo",
        9100: "Impressão em rede",
        27036: "Possível serviço Steam",
    }

    servico = servicos.get(porta, "Desconhecido")
    if porta in servicos:
        identificacao = "Associação provável pela porta; não confirmada"
    else:
        identificacao = "Serviço não identificado"

    return servico, identificacao


def salvar_log(host, porta, status, detalhes):
    """Mantém o formato CSV original para preservar compatibilidade."""
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    arquivo_existe = ARQUIVO_LOG.exists()

    with open(ARQUIVO_LOG, "a", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo)

        if not arquivo_existe or ARQUIVO_LOG.stat().st_size == 0:
            escritor.writerow([
                "Data e hora", "Host", "Porta", "Status", "Detalhes"
            ])

        escritor.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            host, porta, status, detalhes
        ])


def inserir_resultado(
    host, porta, status, detalhes, servico="-", identificacao="-"
):
    tabela.insert(
        "",
        0,
        values=(
            datetime.now().strftime("%H:%M:%S"),
            host,
            porta,
            status,
            servico,
            identificacao,
            detalhes
        )
    )


def descobrir_dispositivos():
    botao_descobrir.config(state="disabled")
    botao_analisar.config(state="disabled")
    rotulo_status.config(text="Detectando a rede local e procurando dispositivos...")

    threading.Thread(
        target=executar_descoberta,
        daemon=True
    ).start()


def executar_descoberta():
    try:
        rede_local, interface = obter_rede_local()
        resultado = subprocess.run(
            ["nmap", "-sn", rede_local],
            capture_output=True,
            text=True,
            timeout=90,
            check=False
        )

        if resultado.returncode != 0:
            detalhe = resultado.stderr.strip() or resultado.stdout.strip()
            raise RuntimeError(detalhe or "O Nmap retornou um erro.")

        macs_vizinhos = obter_macs_vizinhos()
        dispositivos = []
        blocos = re.split(r"(?m)^Nmap scan report for ", resultado.stdout)

        for bloco in blocos[1:]:
            linhas = bloco.splitlines()
            if not linhas:
                continue
            identificacao = linhas[0].strip()
            if not any("Host is up" in linha for linha in linhas[1:]):
                continue

            correspondencia = re.match(r"^(.*?) \(([^)]+)\)$", identificacao)
            if correspondencia:
                nome = correspondencia.group(1).strip()
                ip = correspondencia.group(2).strip()
            else:
                nome = identificacao
                ip = identificacao

            mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})(?: \((.*?)\))?", bloco)
            mac = mac_match.group(1).upper() if mac_match else macs_vizinhos.get(ip, "")
            fabricante = mac_match.group(2).strip() if mac_match and mac_match.group(2) else "Desconhecido"
            fabricante = resolver_fabricante(mac, fabricante)
            dispositivos.append({
                "ip": ip, "nome": nome or ip, "mac": mac,
                "tipo_mac": classificar_tipo_mac(mac),
                "fabricante": fabricante
            })

        fila_resultados.put(("descoberta_concluida", dispositivos, rede_local, interface))

    except FileNotFoundError:
        fila_resultados.put(("erro_descoberta", "Nmap não encontrado. Instale com: sudo apt install nmap"))
    except subprocess.TimeoutExpired:
        fila_resultados.put(("erro_descoberta", "A descoberta excedeu o tempo limite."))
    except (OSError, RuntimeError) as erro:
        fila_resultados.put(("erro_descoberta", str(erro)))


def analisar_dispositivo():
    selecionados_dispositivos = tabela_dispositivos.selection()
    selecionados_atividade = tabela.selection()

    if selecionados_dispositivos:
        valores = tabela_dispositivos.item(selecionados_dispositivos[0], "values")
        host = str(valores[0]).strip()
    elif selecionados_atividade:
        valores = tabela.item(selecionados_atividade[0], "values")
        if len(valores) < 7 or valores[3] != "ATIVO":
            messagebox.showwarning(
                "Seleção inválida",
                "Na aba Atividade, selecione uma linha de dispositivo com status ATIVO."
            )
            return
        host = str(valores[1]).strip()
    else:
        messagebox.showwarning(
            "Selecione um dispositivo",
            "Selecione um dispositivo na aba Dispositivos ou uma descoberta na aba Atividade."
        )
        return

    if not host:
        messagebox.showerror("Erro", "O dispositivo selecionado não tem IP.")
        return

    botao_analisar.config(state="disabled")
    rotulo_status.config(text=f"Analisando portas TCP de {host}...")

    threading.Thread(
        target=executar_analise_portas,
        args=(host,),
        daemon=True
    ).start()


def executar_analise_portas(host):
    resultados = []

    for porta in PORTAS_ANALISAR:
        servico, identificacao = identificar_servico(porta)

        try:
            with socket.create_connection((host, porta), timeout=0.6):
                status = "ABERTA"
                detalhes = "Conexão TCP estabelecida."
        except socket.timeout:
            status = "SEM CONEXÃO"
            detalhes = (
                "Tempo limite; a porta não foi confirmada como aberta."
            )
        except OSError as erro:
            status = "SEM CONEXÃO"
            detalhes = f"Conexão não estabelecida: {erro}"

        detalhes_log = (
            f"{detalhes} | Serviço provável: {servico} | "
            f"Identificação: {identificacao}"
        )
        resultados.append((
            porta, status, detalhes, servico, identificacao, detalhes_log
        ))
        salvar_log(host, porta, status, detalhes_log)

    fila_resultados.put(("analise_concluida", host, resultados))


def editar_nome_personalizado():
    selecionados = tabela_dispositivos.selection()
    if not selecionados:
        messagebox.showwarning("Selecione um dispositivo", "Selecione um dispositivo na aba Dispositivos.")
        return

    chave_linha = selecionados[0]
    item = dispositivos_atuais.get(chave_linha)
    if not item:
        messagebox.showerror("Dispositivo indisponível", "Não foi possível localizar os dados do dispositivo selecionado.")
        return

    ip = item.get("ip", "")
    mac = (item.get("mac") or "").strip().upper()
    chave = mac or ip
    atual = obter_nome_personalizado(ip, mac)

    dialogo = tk.Toplevel(janela)
    dialogo.title("Nome personalizado do dispositivo")
    dialogo.transient(janela)
    dialogo.grab_set()
    dialogo.resizable(False, False)
    quadro = ttk.Frame(dialogo, padding=14)
    quadro.pack(fill="both", expand=True)
    ttk.Label(quadro, text=f"Dispositivo: {ip}", font=("Arial", 10, "bold")).pack(anchor="w")
    ttk.Label(quadro, text=f"MAC: {mac or 'Não identificado'}").pack(anchor="w", pady=(2, 8))
    ttk.Label(quadro, text="Nome personalizado (deixe vazio para remover):").pack(anchor="w")
    campo_nome = ttk.Entry(quadro, width=42)
    campo_nome.pack(fill="x", pady=(4, 10))
    campo_nome.insert(0, atual)
    campo_nome.focus_set()

    def salvar_nome():
        nome = campo_nome.get().strip()
        if len(nome) > 60:
            messagebox.showwarning("Nome muito longo", "Use no máximo 60 caracteres.", parent=dialogo)
            return
        if nome:
            nomes_personalizados[chave] = {"ip": ip, "mac": mac, "nome": nome}
        else:
            nomes_personalizados.pop(chave, None)
        try:
            salvar_nomes_personalizados()
        except OSError as erro:
            messagebox.showerror("Erro ao salvar", f"Não foi possível salvar o nome: {erro}", parent=dialogo)
            return

        item["nome_personalizado"] = nome
        # Mantém o alias no inventário local para preservar a escolha entre varreduras.
        chave_inventario = chave_dispositivo(ip, mac)
        if chave_inventario in inventario_inteligente:
            inventario_inteligente[chave_inventario]["nome_personalizado"] = nome
            salvar_inventario_inteligente()
        valores = list(tabela_dispositivos.item(chave_linha, "values"))
        if len(valores) > 4:
            valores[4] = nome
            tabela_dispositivos.item(chave_linha, values=tuple(valores))
        rotulo_status.config(text=f"Nome personalizado {'salvo' if nome else 'removido'} para {ip}.")
        dialogo.destroy()

    botoes = ttk.Frame(quadro)
    botoes.pack(fill="x")
    ttk.Button(botoes, text="Salvar", command=salvar_nome).pack(side="left", padx=(0, 8))
    ttk.Button(botoes, text="Cancelar", command=dialogo.destroy).pack(side="left")
    dialogo.bind("<Return>", lambda _evento: salvar_nome())
    dialogo.bind("<Escape>", lambda _evento: dialogo.destroy())


def mostrar_detalhes_dispositivo():
    """Exibe um resumo do dispositivo selecionado e suas observações recentes."""
    selecionados = tabela_dispositivos.selection()
    if not selecionados:
        messagebox.showwarning("Selecione um dispositivo", "Selecione um dispositivo na aba Dispositivos.")
        return

    item = dispositivos_atuais.get(selecionados[0])
    if not item:
        messagebox.showerror("Dispositivo indisponível", "Não foi possível localizar os dados do dispositivo selecionado.")
        return

    ip = item.get("ip", "")
    mac = (item.get("mac") or "").strip().upper()
    chave = mac or ip
    alias = obter_nome_personalizado(ip, mac) or "Não definido"
    confiavel = "Sim" if chave in dispositivos_conhecidos else "Não"

    dialogo = tk.Toplevel(janela)
    dialogo.title(f"Detalhes do dispositivo — {ip}")
    dialogo.transient(janela)
    dialogo.geometry("720x560")
    dialogo.minsize(560, 420)

    quadro = ttk.Frame(dialogo, padding=14)
    quadro.pack(fill="both", expand=True)
    ttk.Label(quadro, text=alias if alias != "Não definido" else (item.get("nome") or ip),
              font=("Arial", 15, "bold")).pack(anchor="w", pady=(0, 8))

    dados = [
        ("IP atual", ip),
        ("Endereço MAC", mac or "Não identificado"),
        ("Hostname original", item.get("nome", "Não identificado")),
        ("Nome personalizado", alias),
        ("Tipo de MAC", item.get("tipo_mac", classificar_tipo_mac(mac))),
        ("Fabricante provável", item.get("fabricante", "Desconhecido")),
        ("Tipo provável", item.get("tipo", "Não identificado")),
        ("Classificação", item.get("classificacao", "Não classificado")),
        ("Na lista de confiáveis", confiavel),
        ("Primeira observação", item.get("primeira_observacao", "Não disponível")),
        ("Última observação", item.get("ultima_observacao", "Não disponível")),
        ("Aparições registradas", str(item.get("aparicoes", 0))),
        ("Motivo / evidência", item.get("motivo", "Sem detalhes")),
    ]
    quadro_dados = ttk.LabelFrame(quadro, text="Informações", padding=8)
    quadro_dados.pack(fill="x", pady=(0, 10))
    for indice, (rotulo, valor) in enumerate(dados):
        ttk.Label(quadro_dados, text=f"{rotulo}:", font=("Arial", 9, "bold")).grid(
            row=indice, column=0, sticky="nw", padx=(0, 8), pady=2)
        ttk.Label(quadro_dados, text=str(valor), wraplength=500).grid(
            row=indice, column=1, sticky="nw", pady=2)
    quadro_dados.columnconfigure(1, weight=1)

    quadro_historico = ttk.LabelFrame(quadro, text="Últimas observações registradas", padding=8)
    quadro_historico.pack(fill="both", expand=True)
    texto = tk.Text(quadro_historico, height=7, wrap="word", state="normal")
    barra = ttk.Scrollbar(quadro_historico, orient="vertical", command=texto.yview)
    texto.configure(yscrollcommand=barra.set)
    texto.pack(side="left", fill="both", expand=True)
    barra.pack(side="right", fill="y")

    historico = []
    try:
        if ARQUIVO_HISTORICO.exists():
            with open(ARQUIVO_HISTORICO, newline="", encoding="utf-8") as arquivo:
                for linha in csv.DictReader(arquivo):
                    linha_mac = (linha.get("MAC") or "").strip().upper()
                    linha_ip = (linha.get("IP") or "").strip()
                    if (mac and linha_mac == mac) or (not mac and linha_ip == ip):
                        historico.append(linha)
    except (OSError, csv.Error) as erro:
        historico.append({"Data e hora": "", "Classificação": "Erro ao ler histórico", "Detalhes": str(erro)})

    for linha in historico[-10:][::-1]:
        data = linha.get("Data e hora", "")
        classificacao = linha.get("Classificação", "")
        detalhes = linha.get("Detalhes", "")
        texto.insert("end", f"{data} | {classificacao}\n{detalhes}\n\n")
    if not historico:
        texto.insert("end", "Ainda não há observações históricas para este dispositivo.")
    texto.configure(state="disabled")
    ttk.Button(quadro, text="Fechar", command=dialogo.destroy).pack(anchor="e", pady=(8, 0))


def confiar_dispositivo_selecionado():
    selecionados = tabela_dispositivos.selection()
    if not selecionados:
        messagebox.showwarning("Selecione um dispositivo", "Selecione um dispositivo na aba Dispositivos.")
        return
    valores = tabela_dispositivos.item(selecionados[0], "values")
    ip, mac = str(valores[0]), str(valores[1])
    nome = str(valores[4] or valores[3]) if len(valores) > 4 else str(valores[3])
    if mac == "Não identificado":
        mac = ""
        if not messagebox.askyesno(
            "Confirmar confiança por IP",
            "O MAC não foi identificado. A confiança será baseada apenas no IP e será menos confiável. Deseja continuar?"
        ):
            return
    chave = mac.upper() or ip
    dispositivos_conhecidos[chave] = {
        "ip": ip, "mac": mac.upper(), "nome": nome,
        "desde": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    salvar_dispositivos_conhecidos()
    atualizar_classificacao_dispositivos()
    atualizar_painel_seguranca()
    rotulo_status.config(text=f"Dispositivo {ip} registrado como confiável.")


def remover_confianca_selecionado():
    selecionados = tabela_dispositivos.selection()
    if not selecionados:
        messagebox.showwarning("Selecione um dispositivo", "Selecione um dispositivo na aba Dispositivos.")
        return
    valores = tabela_dispositivos.item(selecionados[0], "values")
    ip, mac = str(valores[0]), str(valores[1])
    chave = mac.upper() if mac != "Não identificado" else ip
    if chave not in dispositivos_conhecidos:
        messagebox.showinfo("Sem registro", "Esse dispositivo não está na lista de confiança.")
        return
    if messagebox.askyesno("Remover confiança", f"Remover {ip} da lista de dispositivos confiáveis?"):
        dispositivos_conhecidos.pop(chave, None)
        salvar_dispositivos_conhecidos()
        atualizar_classificacao_dispositivos()
        atualizar_painel_seguranca()
        rotulo_status.config(text=f"Confiança removida para {ip}.")


def atualizar_classificacao_dispositivos():
    for chave, item in dispositivos_atuais.items():
        classificacao, motivo = classificar_dispositivo(item["ip"], item["mac"])
        item["classificacao"] = classificacao
        item["motivo"] = motivo
        if tabela_dispositivos.exists(chave):
            tabela_dispositivos.item(
                chave,
                values=(item["ip"], item["mac"] or "Não identificado", item.get("tipo_mac", classificar_tipo_mac(item["mac"])), item["nome"],
                        item.get("nome_personalizado", obter_nome_personalizado(item["ip"], item["mac"])),
                        item.get("fabricante", "Desconhecido"), item.get("tipo", "Não identificado"),
                        classificacao, item.get("primeira_observacao", "")[:10],
                        item["ultima_observacao"].split(" ")[-1], item.get("aparicoes", 1), motivo),
                tags=("alerta",) if classificacao.startswith(("DESCONHECIDO", "ALERTA")) else ()
            )


def aplicar_filtro_inventario(_evento=None):
    """Reaplica o filtro sempre sobre o inventário completo, nunca sobre o resultado anterior.

    O Treeview mantém itens destacados fora da lista visual. Por isso, usamos
    dispositivos_atuais como fonte canônica e reanexamos todos os itens antes
    de calcular quais devem permanecer visíveis.
    """
    filtro = filtro_inventario_var.get()

    # Primeiro restaura todos os itens conhecidos na tabela. Isso impede que
    # a troca de filtro opere somente sobre as linhas visíveis do filtro anterior.
    for chave in dispositivos_atuais:
        if tabela_dispositivos.exists(chave):
            tabela_dispositivos.reattach(chave, "", "end")

    # Depois calcula a visibilidade de cada item a partir do conjunto completo.
    for chave, item in dispositivos_atuais.items():
        if not tabela_dispositivos.exists(chave):
            continue
        valores = tabela_dispositivos.item(chave, "values")
        # Colunas: IP, MAC, Tipo MAC, hostname, nome personalizado, fabricante, tipo, classificação, ...
        classificacao = str(valores[7]) if len(valores) > 7 else str(item.get("classificacao", ""))
        tipo_mac = str(valores[2]) if len(valores) > 2 else str(item.get("tipo_mac", ""))
        fabricante = str(valores[5]) if len(valores) > 5 else str(item.get("fabricante", "Desconhecido"))
        mac = str(valores[1]) if len(valores) > 1 else str(item.get("mac") or "Não identificado")

        if filtro == "Todos":
            mostrar = True
        elif filtro == "Desconhecidos / alertas":
            mostrar = classificacao.startswith(("DESCONHECIDO", "ALERTA"))
        elif filtro == "MAC local/privado":
            mostrar = "Local/privado" in tipo_mac
        elif filtro == "Fabricante identificado":
            mostrar = fabricante not in ("Desconhecido", "Não confiável pelo prefixo", "", "None")
        elif filtro == "Sem MAC":
            mostrar = tipo_mac == "Indisponível" or mac == "Não identificado"
        else:
            mostrar = True

        if mostrar:
            tabela_dispositivos.reattach(chave, "", "end")
        else:
            tabela_dispositivos.detach(chave)


def classificar_prioridade_evento(tipo):
    """Atribui prioridade operacional ao evento; não é uma conclusão de ataque."""
    tipo_normalizado = (tipo or "").strip().upper()
    if "MAC ALTERADO" in tipo_normalizado:
        return "MÉDIA"
    if "NOVO DISPOSITIVO" in tipo_normalizado:
        return "MÉDIA"
    if "NÃO DETECTADO" in tipo_normalizado or "NAO DETECTADO" in tipo_normalizado:
        return "BAIXA"
    if "PRIMEIRA OBSERVAÇÃO" in tipo_normalizado or "PRIMEIRA OBSERVACAO" in tipo_normalizado:
        return "INFO"
    return "INFO"



def gerar_id_alerta(evento):
    """Gera uma chave estável para vincular o evento ao seu estado de revisão."""
    campos = ("Data e hora", "Evento", "IP", "MAC", "Nome", "Detalhes")
    conteudo = "|".join(str(evento.get(campo, "")) for campo in campos)
    return hashlib.sha256(conteudo.encode("utf-8")).hexdigest()


def carregar_revisoes_alertas():
    """Carrega do CSV os estados de revisão dos alertas."""
    revisoes_alertas.clear()
    if not ARQUIVO_REVISAO_ALERTAS.exists():
        return
    try:
        with open(ARQUIVO_REVISAO_ALERTAS, newline="", encoding="utf-8") as arquivo:
            for linha in csv.DictReader(arquivo):
                identificador = (linha.get("ID") or "").strip()
                status = (linha.get("Status") or "").strip()
                if identificador and status in ("Pendente", "Revisado"):
                    revisoes_alertas[identificador] = status
    except (OSError, csv.Error) as erro:
        print(f"Não foi possível carregar as revisões dos alertas: {erro}")


def salvar_revisoes_alertas():
    """Salva os estados de revisão em arquivo separado dos eventos originais."""
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    temporario = ARQUIVO_REVISAO_ALERTAS.with_suffix(".tmp")
    with open(temporario, "w", newline="", encoding="utf-8") as arquivo:
        campos = ["ID", "Status"]
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for identificador, status in revisoes_alertas.items():
            escritor.writerow({"ID": identificador, "Status": status})
    temporario.replace(ARQUIVO_REVISAO_ALERTAS)


def atualizar_central_alertas():
    """Atualiza a lista de eventos com filtros de prioridade e revisão."""
    if not all(nome in globals() for nome in ("tabela_alertas", "filtro_prioridade_alertas_var", "filtro_status_alertas_var")):
        return
    for item in tabela_alertas.get_children():
        tabela_alertas.delete(item)

    registros = []
    if ARQUIVO_EVENTOS.exists():
        try:
            with open(ARQUIVO_EVENTOS, newline="", encoding="utf-8") as arquivo:
                registros = list(csv.DictReader(arquivo))
        except (OSError, csv.Error) as erro:
            print(f"Não foi possível ler os eventos para a central de alertas: {erro}")

    filtro_prioridade = filtro_prioridade_alertas_var.get()
    filtro_status = filtro_status_alertas_var.get()
    for evento in reversed(registros):
        prioridade = classificar_prioridade_evento(evento.get("Evento", ""))
        identificador = gerar_id_alerta(evento)
        status = revisoes_alertas.get(identificador, "Pendente")
        if filtro_prioridade != "Todas" and prioridade != filtro_prioridade:
            continue
        if filtro_status == "Pendentes" and status != "Pendente":
            continue
        if filtro_status == "Revisados" and status != "Revisado":
            continue
        tabela_alertas.insert(
            "", "end", iid=identificador,
            values=(prioridade, status, evento.get("Data e hora", ""),
                    evento.get("Evento", ""), evento.get("IP", ""),
                    evento.get("MAC", ""), evento.get("Nome", ""),
                    evento.get("Detalhes", "")),
            tags=(prioridade.lower(), status.lower())
        )


def alterar_status_alerta(novo_status):
    """Marca o alerta selecionado como revisado ou pendente."""
    selecionados = tabela_alertas.selection()
    if not selecionados:
        messagebox.showinfo("Central de alertas", "Selecione um alerta na lista primeiro.")
        return
    revisoes_alertas[selecionados[0]] = novo_status
    try:
        salvar_revisoes_alertas()
    except OSError as erro:
        messagebox.showerror("Erro ao salvar", f"Não foi possível salvar a revisão do alerta:\n{erro}")
        return
    atualizar_central_alertas()
    atualizar_painel_seguranca()


def atualizar_painel_seguranca():
    """Atualiza os indicadores e as ocorrências recentes do painel principal."""
    total = len(dispositivos_atuais)
    confiaveis = sum(
        1 for item in dispositivos_atuais.values()
        if str(item.get("classificacao", "")).startswith("CONHECIDO")
    )
    alertas = sum(
        1 for item in dispositivos_atuais.values()
        if str(item.get("classificacao", "")).startswith(("DESCONHECIDO", "ALERTA"))
    )
    rotulo_total.config(text=str(total))
    rotulo_confiaveis.config(text=str(confiaveis))
    rotulo_alertas.config(text=str(alertas))

    linhas = []
    if ARQUIVO_EVENTOS.exists():
        try:
            with open(ARQUIVO_EVENTOS, newline="", encoding="utf-8") as arquivo:
                registros = list(csv.DictReader(arquivo))
            for evento in reversed(registros[-5:]):
                hora = evento.get("Data e hora", "")
                tipo = evento.get("Evento", "Evento")
                ip = evento.get("IP", "")
                mac = (evento.get("MAC", "") or "").strip()
                if mac.upper() in ("NÃO IDENTIFICADO", "NAO IDENTIFICADO", "N/A", "-"):
                    mac = ""

                # Quando houver apelido personalizado, mostrá-lo no lugar do rótulo
                # genérico do evento de descoberta. Os demais tipos de evento ficam iguais.
                nome_personalizado = obter_nome_personalizado(ip, mac)
                if nome_personalizado and tipo.upper() in (
                    "NOVO DISPOSITIVO", "PRIMEIRA OBSERVAÇÃO", "PRIMEIRA OBSERVACAO"
                ):
                    tipo_exibicao = nome_personalizado
                else:
                    tipo_exibicao = tipo

                prioridade = classificar_prioridade_evento(tipo)
                linhas.append(f"[{prioridade}] {hora} | {tipo_exibicao} | {ip}")
        except (OSError, csv.Error):
            linhas = []
    rotulo_eventos_recentes.config(
        text="\n".join(linhas) if linhas else "Nenhum evento registrado ainda. Execute uma descoberta da rede."
    )


def processar_resultados():
    try:
        while True:
            mensagem = fila_resultados.get_nowait()
            tipo = mensagem[0]

            if tipo == "descoberta_concluida":
                dispositivos = mensagem[1]
                rede_local = mensagem[2] if len(mensagem) > 2 else "rede detectada"
                interface = mensagem[3] if len(mensagem) > 3 else "interface ativa"
                rotulo_rede.config(text=f"Rede detectada: {rede_local} | Interface: {interface}")
                eventos = comparar_varreduras(dispositivos)
                dispositivos_atuais.clear()
                for linha in tabela_dispositivos.get_children():
                    tabela_dispositivos.delete(linha)
                for tipo_evento, item_evento, detalhe_evento in eventos:
                    salvar_log(item_evento["ip"], "-", tipo_evento,
                               f"{detalhe_evento} | MAC: {item_evento.get('mac') or 'não identificado'}")
                    inserir_resultado(item_evento["ip"], "-", tipo_evento,
                                      detalhe_evento, "Evento de rede", "Observação; requer validação")
                for item in dispositivos:
                    ip, nome, mac = item["ip"], item["nome"], item["mac"]
                    fabricante = item.get("fabricante", "Desconhecido")
                    metadados = atualizar_inventario_inteligente(ip, mac, nome, fabricante)
                    classificacao, motivo = classificar_dispositivo(ip, mac)
                    chave = mac or ip
                    dispositivos_atuais[chave] = {
                        "ip": ip, "nome": nome, "nome_personalizado": obter_nome_personalizado(ip, mac), "mac": mac,
                        "tipo_mac": metadados.get("tipo_mac", classificar_tipo_mac(mac)),
                        "fabricante": metadados["fabricante"], "tipo": metadados["tipo"],
                        "primeira_observacao": metadados["primeira_observacao"],
                        "ultima_observacao": metadados["ultima_observacao"],
                        "aparicoes": metadados["aparicoes"],
                        "classificacao": classificacao, "motivo": motivo,
                    }
                    tipo_mac = metadados.get("tipo_mac", classificar_tipo_mac(mac))
                    detalhes = f"Nome: {nome} | MAC: {mac or 'não identificado'} | Tipo de MAC: {tipo_mac} | {motivo}"
                    salvar_log(ip, "-", classificacao, detalhes)
                    salvar_observacao_dispositivo(ip, mac, nome, classificacao, motivo)
                    inserir_resultado(
                        ip, "-", classificacao, detalhes,
                        "Dispositivo", "Inventário local"
                    )
                    if classificacao.startswith("DESCONHECIDO") or classificacao.startswith("ALERTA"):
                        tabela_dispositivos.tag_configure("alerta", foreground="#f87171")
                    tabela_dispositivos.insert(
                        "", "end", iid=chave,
                        values=(ip, mac or "Não identificado", metadados.get("tipo_mac", classificar_tipo_mac(mac)), nome,
                                obter_nome_personalizado(ip, mac), metadados["fabricante"], metadados["tipo"], classificacao,
                                metadados["primeira_observacao"][:10],
                                datetime.now().strftime("%H:%M:%S"),
                                metadados["aparicoes"], motivo),
                        tags=("alerta",) if classificacao.startswith(("DESCONHECIDO", "ALERTA")) else ()
                    )

                salvar_inventario_inteligente()
                aplicar_filtro_inventario()
                atualizar_painel_seguranca()
                atualizar_central_alertas()
                suspeitos = sum(1 for d in dispositivos_atuais.values()
                                if d["classificacao"].startswith(("DESCONHECIDO", "ALERTA")))
                novos_eventos = sum(1 for evento in eventos if evento[0] in ("NOVO DISPOSITIVO", "MAC ALTERADO NO IP"))
                ausentes = sum(1 for evento in eventos if evento[0] == "NÃO DETECTADO NESTA VARREDURA")
                rotulo_status.config(
                    text=(f"Varredura concluída em {rede_local} ({interface}): "
                          f"{len(dispositivos)} dispositivo(s); {suspeitos} desconhecido(s)/com alerta; "
                          f"{novos_eventos} evento(s) novo(s)/MAC alterado; {ausentes} não detectado(s). "
                          "Ausência ou MAC alterado não confirma invasão.")
                )
                botao_descobrir.config(state="normal")
                botao_analisar.config(state="normal")
                botao_confiavel.config(state="normal")
                botao_remover_confianca.config(state="normal")

            elif tipo == "analise_concluida":
                _, host, resultados = mensagem
                abertas = 0

                for (
                    porta, status, detalhes, servico,
                    identificacao, detalhes_log
                ) in resultados:
                    inserir_resultado(
                        host, porta, status, detalhes,
                        servico, identificacao
                    )
                    if status == "ABERTA":
                        abertas += 1

                rotulo_status.config(
                    text=(
                        f"Análise de {host} concluída: "
                        f"{abertas} porta(s) aberta(s) entre "
                        f"{len(resultados)} verificadas."
                    )
                )
                botao_analisar.config(state="normal")

            elif tipo == "erro_descoberta":
                rotulo_status.config(text="Falha na descoberta.")
                messagebox.showerror("Erro na descoberta", mensagem[1])
                botao_descobrir.config(state="normal")
                botao_analisar.config(state="normal")

    except queue.Empty:
        pass

    janela.after(100, processar_resultados)


# Interface gráfica — redesign escuro profissional
carregar_base_oui()
carregar_dispositivos_conhecidos()
carregar_estado_anterior()
carregar_inventario_inteligente()
carregar_nomes_personalizados()
carregar_revisoes_alertas()

janela = tk.Tk()
janela.title("NetWatch | Monitor de Rede")
janela.geometry("1480x850")
janela.minsize(1100, 650)
janela.configure(bg="#0b1220")

# Paleta consistente para toda a interface ttk.
COR_FUNDO = "#0b1220"
COR_PAINEL = "#111c2e"
COR_PAINEL_ALT = "#162338"
COR_BORDA = "#26364d"
COR_TEXTO = "#e5edf7"
COR_TEXTO_SEC = "#9fb0c7"
COR_AZUL = "#3b82f6"
COR_VERDE = "#22c55e"
COR_AMARELO = "#fbbf24"
COR_VERMELHO = "#f87171"

estilo = ttk.Style(janela)
try:
    estilo.theme_use("clam")
except tk.TclError:
    pass

estilo.configure(".", background=COR_FUNDO, foreground=COR_TEXTO, font=("DejaVu Sans", 10))
estilo.configure("TFrame", background=COR_FUNDO)
estilo.configure("Panel.TFrame", background=COR_PAINEL)
estilo.configure("Card.TFrame", background=COR_PAINEL_ALT, relief="flat")
estilo.configure("TLabel", background=COR_FUNDO, foreground=COR_TEXTO)
estilo.configure("Muted.TLabel", background=COR_FUNDO, foreground=COR_TEXTO_SEC, font=("DejaVu Sans", 9))
estilo.configure("Panel.TLabel", background=COR_PAINEL, foreground=COR_TEXTO)
estilo.configure("CardTitle.TLabel", background=COR_PAINEL_ALT, foreground=COR_TEXTO_SEC, font=("DejaVu Sans", 9, "bold"))
estilo.configure("CardValue.TLabel", background=COR_PAINEL_ALT, foreground=COR_TEXTO, font=("DejaVu Sans", 23, "bold"))
estilo.configure("Brand.TLabel", background=COR_FUNDO, foreground="#f8fafc", font=("DejaVu Sans", 23, "bold"))
estilo.configure("Subtitle.TLabel", background=COR_FUNDO, foreground=COR_TEXTO_SEC, font=("DejaVu Sans", 10))
estilo.configure("Section.TLabelframe", background=COR_PAINEL, bordercolor=COR_BORDA, relief="flat")
estilo.configure("Section.TLabelframe.Label", background=COR_PAINEL, foreground=COR_TEXTO, font=("DejaVu Sans", 10, "bold"))
estilo.configure("TButton", background=COR_PAINEL_ALT, foreground=COR_TEXTO, bordercolor=COR_BORDA, padding=(12, 8), focusthickness=0)
estilo.map("TButton", background=[("active", "#263b59"), ("disabled", "#172235")], foreground=[("disabled", "#64748b")])
estilo.configure("Accent.TButton", background=COR_AZUL, foreground="#ffffff", bordercolor=COR_AZUL, font=("DejaVu Sans", 10, "bold"), padding=(14, 9))
estilo.map("Accent.TButton", background=[("active", "#2563eb"), ("disabled", "#334155")], foreground=[("disabled", "#94a3b8")])
estilo.configure("TEntry", fieldbackground="#0d1727", foreground=COR_TEXTO, insertcolor=COR_TEXTO, bordercolor=COR_BORDA, padding=6)
estilo.configure("TCombobox", fieldbackground="#0d1727", background=COR_PAINEL_ALT, foreground=COR_TEXTO, arrowcolor=COR_TEXTO, bordercolor=COR_BORDA, padding=5)
estilo.map("TCombobox", fieldbackground=[("readonly", "#0d1727")], foreground=[("readonly", COR_TEXTO)], selectbackground=[("readonly", COR_AZUL)], selectforeground=[("readonly", "#ffffff")])
estilo.configure("TNotebook", background=COR_FUNDO, bordercolor=COR_FUNDO, tabmargins=(2, 5, 2, 0))
estilo.configure("TNotebook.Tab", background=COR_PAINEL, foreground=COR_TEXTO_SEC, padding=(18, 10), bordercolor=COR_BORDA, font=("DejaVu Sans", 10, "bold"))
estilo.map("TNotebook.Tab", background=[("selected", COR_AZUL), ("active", COR_PAINEL_ALT)], foreground=[("selected", "#ffffff"), ("active", COR_TEXTO)])
estilo.configure("Treeview", background="#0e1929", fieldbackground="#0e1929", foreground=COR_TEXTO, bordercolor=COR_BORDA, rowheight=30, font=("DejaVu Sans", 9))
estilo.configure("Treeview.Heading", background=COR_PAINEL_ALT, foreground=COR_TEXTO, relief="flat", padding=(8, 9), font=("DejaVu Sans", 9, "bold"))
estilo.map("Treeview", background=[("selected", "#1d4ed8")], foreground=[("selected", "#ffffff")])
estilo.configure("Horizontal.TScrollbar", background=COR_PAINEL_ALT, troughcolor=COR_FUNDO, bordercolor=COR_FUNDO, arrowcolor=COR_TEXTO_SEC)
estilo.configure("Vertical.TScrollbar", background=COR_PAINEL_ALT, troughcolor=COR_FUNDO, bordercolor=COR_FUNDO, arrowcolor=COR_TEXTO_SEC)

# Cabeçalho do produto e ações principais.
cabecalho = ttk.Frame(janela, padding=(24, 18, 24, 12))
cabecalho.pack(fill="x")
identidade = ttk.Frame(cabecalho)
identidade.pack(side="left", fill="x", expand=True)
titulo = ttk.Label(identidade, text="NETWATCH", style="Brand.TLabel")
titulo.pack(anchor="w")
subtitulo = ttk.Label(identidade, text="MONITORAMENTO DE REDE  /  INVENTÁRIO  /  SEGURANÇA", style="Subtitle.TLabel")
subtitulo.pack(anchor="w", pady=(2, 8))
rotulo_rede = ttk.Label(identidade, text="Rede local: será detectada automaticamente ao iniciar a descoberta.", style="Muted.TLabel")
rotulo_rede.pack(anchor="w")

acoes = ttk.Frame(cabecalho)
acoes.pack(side="right", anchor="center", padx=(16, 0))
botao_descobrir = ttk.Button(acoes, text="⟳  Descobrir dispositivos", style="Accent.TButton", command=descobrir_dispositivos)
botao_descobrir.pack(fill="x", pady=(0, 8))
botao_analisar = ttk.Button(acoes, text="⌕  Analisar portas do selecionado", command=analisar_dispositivo)
botao_analisar.pack(fill="x")

separador_topo = ttk.Separator(janela, orient="horizontal")
separador_topo.pack(fill="x", padx=24, pady=(0, 14))

# Resumo em cartões, com hierarquia visual e indicadores de leitura rápida.
painel_seguranca = ttk.LabelFrame(janela, text="  VISÃO GERAL  ", style="Section.TLabelframe", padding=(14, 12))
painel_seguranca.pack(fill="x", padx=24, pady=(0, 12))
indicadores = ttk.Frame(painel_seguranca, style="Panel.TFrame")
indicadores.pack(fill="x")
for coluna in range(3):
    indicadores.columnconfigure(coluna, weight=1, uniform="kpi")

def criar_indicador(pai, coluna, titulo_indicador):
    bloco = ttk.Frame(pai, style="Card.TFrame", padding=(16, 12))
    bloco.grid(row=0, column=coluna, sticky="nsew", padx=(0 if coluna == 0 else 6, 6 if coluna < 2 else 0), pady=2)
    ttk.Label(bloco, text=titulo_indicador.upper(), style="CardTitle.TLabel").pack(anchor="w")
    valor = ttk.Label(bloco, text="0", style="CardValue.TLabel")
    valor.pack(anchor="w", pady=(5, 0))
    return valor

rotulo_total = criar_indicador(indicadores, 0, "Dispositivos encontrados")
rotulo_confiaveis = criar_indicador(indicadores, 1, "Dispositivos confiáveis")
rotulo_alertas = criar_indicador(indicadores, 2, "Desconhecidos / alertas")

linha_eventos = ttk.Frame(painel_seguranca, style="Panel.TFrame")
linha_eventos.pack(fill="x", pady=(12, 0))
ttk.Label(linha_eventos, text="EVENTOS RECENTES", style="Panel.TLabel", font=("DejaVu Sans", 9, "bold")).pack(anchor="w", pady=(0, 5))
rotulo_eventos_recentes = ttk.Label(
    linha_eventos,
    text="Nenhum evento registrado ainda. Execute uma descoberta da rede.",
    style="Panel.TLabel", justify="left", anchor="w", wraplength=1350
)
rotulo_eventos_recentes.pack(fill="x", anchor="w")
ttk.Label(
    linha_eventos,
    text="A prioridade orienta a investigação, mas não confirma invasão. Dispositivos podem ficar indisponíveis por estarem desligados ou em economia de energia.",
    style="Muted.TLabel", wraplength=1350
).pack(fill="x", anchor="w", pady=(6, 0))

abas = ttk.Notebook(janela)
aba_dispositivos = ttk.Frame(abas, padding=12)
aba_atividade = ttk.Frame(abas, padding=12)
aba_alertas = ttk.Frame(abas, padding=12)
abas.add(aba_dispositivos, text="  Dispositivos  ")
abas.add(aba_atividade, text="  Atividade e portas  ")
abas.add(aba_alertas, text="  Central de alertas  ")
abas.pack(fill="both", expand=True, padx=24, pady=(0, 10))

# Central de alertas: filtros e estado de revisão persistente.
barra_alertas = ttk.Frame(aba_alertas)
barra_alertas.pack(fill="x", pady=(0, 8))
ttk.Label(barra_alertas, text="Prioridade:").pack(side="left", padx=(0, 5))
filtro_prioridade_alertas_var = tk.StringVar(value="Todas")
seletor_prioridade_alertas = ttk.Combobox(
    barra_alertas, textvariable=filtro_prioridade_alertas_var, state="readonly", width=12,
    values=("Todas", "MÉDIA", "BAIXA", "INFO")
)
seletor_prioridade_alertas.pack(side="left", padx=(0, 12))
seletor_prioridade_alertas.bind("<<ComboboxSelected>>", lambda _evento: atualizar_central_alertas())
ttk.Label(barra_alertas, text="Revisão:").pack(side="left", padx=(0, 5))
filtro_status_alertas_var = tk.StringVar(value="Todos")
seletor_status_alertas = ttk.Combobox(
    barra_alertas, textvariable=filtro_status_alertas_var, state="readonly", width=12,
    values=("Todos", "Pendentes", "Revisados")
)
seletor_status_alertas.pack(side="left", padx=(0, 12))
seletor_status_alertas.bind("<<ComboboxSelected>>", lambda _evento: atualizar_central_alertas())
ttk.Button(barra_alertas, text="Atualizar lista", command=atualizar_central_alertas).pack(side="left", padx=(0, 8))
ttk.Button(barra_alertas, text="Marcar como revisado", command=lambda: alterar_status_alerta("Revisado")).pack(side="left", padx=(0, 8))
ttk.Button(barra_alertas, text="Marcar como pendente", command=lambda: alterar_status_alerta("Pendente")).pack(side="left")

colunas_alertas = ("prioridade", "revisao", "data", "evento", "ip", "mac", "nome", "detalhes")
tabela_alertas = ttk.Treeview(aba_alertas, columns=colunas_alertas, show="headings", selectmode="browse")
for coluna, texto in [("prioridade", "Prioridade"), ("revisao", "Revisão"), ("data", "Data e hora"),
                      ("evento", "Evento"), ("ip", "IP"), ("mac", "MAC"),
                      ("nome", "Nome"), ("detalhes", "Detalhes")]:
    tabela_alertas.heading(coluna, text=texto)
tabela_alertas.column("prioridade", width=85, stretch=False)
tabela_alertas.column("revisao", width=90, stretch=False)
tabela_alertas.column("data", width=145, stretch=False)
tabela_alertas.column("evento", width=210, stretch=False)
tabela_alertas.column("ip", width=115, stretch=False)
tabela_alertas.column("mac", width=150, stretch=False)
tabela_alertas.column("nome", width=140, stretch=False)
tabela_alertas.column("detalhes", width=420, stretch=True)
tabela_alertas.tag_configure("média", foreground="#f87171")
tabela_alertas.tag_configure("baixa", foreground="#fbbf24")
tabela_alertas.tag_configure("info", foreground="#60a5fa")
tabela_alertas.tag_configure("revisado", foreground="#94a3b8")
scroll_alertas_y = ttk.Scrollbar(aba_alertas, orient="vertical", command=tabela_alertas.yview)
scroll_alertas_x = ttk.Scrollbar(aba_alertas, orient="horizontal", command=tabela_alertas.xview)
tabela_alertas.configure(yscrollcommand=scroll_alertas_y.set, xscrollcommand=scroll_alertas_x.set)
tabela_alertas.pack(fill="both", expand=True)
scroll_alertas_y.pack(side="right", fill="y")
scroll_alertas_x.pack(fill="x")
ttk.Label(aba_alertas, text="A prioridade ajuda a organizar a análise e não confirma invasão. Os estados de revisão são armazenados em logs/revisao_alertas.csv.", wraplength=1200).pack(anchor="w", pady=(8, 0))

barra_filtros = ttk.Frame(aba_dispositivos)
barra_filtros.pack(fill="x", pady=(0, 6))
ttk.Label(barra_filtros, text="Filtrar inventário:").pack(side="left", padx=(0, 8))
filtro_inventario_var = tk.StringVar(value="Todos")
seletor_filtro = ttk.Combobox(
    barra_filtros, textvariable=filtro_inventario_var, state="readonly", width=26,
    values=("Todos", "Desconhecidos / alertas", "MAC local/privado", "Fabricante identificado", "Sem MAC")
)
seletor_filtro.pack(side="left")
seletor_filtro.bind("<<ComboboxSelected>>", aplicar_filtro_inventario)

colunas_disp = ("ip", "mac", "tipo_mac", "nome", "nome_personalizado", "fabricante", "tipo", "classificacao", "primeira", "ultima", "aparicoes", "motivo")
tabela_dispositivos = ttk.Treeview(aba_dispositivos, columns=colunas_disp, show="headings", selectmode="browse")
for coluna, texto in [
    ("ip", "IP"), ("mac", "Endereço MAC"), ("tipo_mac", "Tipo de MAC"), ("nome", "Hostname original"),
    ("nome_personalizado", "Nome personalizado"), ("fabricante", "Fabricante provável"), ("tipo", "Tipo provável"),
    ("classificacao", "Classificação"), ("primeira", "Visto desde"),
    ("ultima", "Última observação"), ("aparicoes", "Aparições"),
    ("motivo", "Motivo / evidência")
]:
    tabela_dispositivos.heading(coluna, text=texto)
tabela_dispositivos.column("ip", width=115, stretch=False)
tabela_dispositivos.column("mac", width=155, stretch=False)
tabela_dispositivos.column("tipo_mac", width=225, stretch=False)
tabela_dispositivos.column("nome", width=145, stretch=False)
tabela_dispositivos.column("nome_personalizado", width=155, stretch=False)
tabela_dispositivos.column("fabricante", width=175, stretch=False)
tabela_dispositivos.column("tipo", width=180, stretch=False)
tabela_dispositivos.column("classificacao", width=175, stretch=False)
tabela_dispositivos.column("primeira", width=100, stretch=False)
tabela_dispositivos.column("ultima", width=90, stretch=False)
tabela_dispositivos.column("aparicoes", width=75, stretch=False)
tabela_dispositivos.column("motivo", width=430, stretch=True)
tabela_dispositivos.tag_configure("alerta", foreground="#f87171")
scroll_disp_y = ttk.Scrollbar(aba_dispositivos, orient="vertical", command=tabela_dispositivos.yview)
scroll_disp_x = ttk.Scrollbar(aba_dispositivos, orient="horizontal", command=tabela_dispositivos.xview)
tabela_dispositivos.configure(yscrollcommand=scroll_disp_y.set, xscrollcommand=scroll_disp_x.set)
tabela_dispositivos.pack(fill="both", expand=True)
scroll_disp_y.pack(side="right", fill="y")
scroll_disp_x.pack(fill="x")

botoes_dispositivos = ttk.Frame(aba_dispositivos)
botoes_dispositivos.pack(fill="x", pady=(8, 0))
botao_confiavel = ttk.Button(botoes_dispositivos, text="Marcar selecionado como confiável", command=confiar_dispositivo_selecionado)
botao_confiavel.pack(side="left", padx=(0, 8))
botao_editar_nome = ttk.Button(botoes_dispositivos, text="Editar nome personalizado", command=editar_nome_personalizado)
botao_editar_nome.pack(side="left", padx=(0, 8))
botao_detalhes = ttk.Button(botoes_dispositivos, text="Detalhes do dispositivo", command=mostrar_detalhes_dispositivo)
botao_detalhes.pack(side="left", padx=(0, 8))
botao_remover_confianca = ttk.Button(botoes_dispositivos, text="Remover confiança", command=remover_confianca_selecionado)
botao_remover_confianca.pack(side="left")
ttk.Label(aba_dispositivos, text="Aviso: novo dispositivo, MAC alterado ou ausência são eventos para investigar, não prova de invasão. Dispositivos podem dormir, trocar de IP ou usar MAC aleatório.", wraplength=1200).pack(anchor="w", pady=(8, 0))

colunas = ("hora", "host", "porta", "status", "servico", "identificacao", "detalhes")
tabela = ttk.Treeview(aba_atividade, columns=colunas, show="headings", selectmode="browse")
for coluna, texto in [("hora", "Horário"), ("host", "Host / IP"), ("porta", "Porta TCP"),
                      ("status", "Status"), ("servico", "Serviço provável"),
                      ("identificacao", "Identificação"), ("detalhes", "Detalhes")]:
    tabela.heading(coluna, text=texto)
tabela.column("hora", width=75, stretch=False)
tabela.column("host", width=130, stretch=False)
tabela.column("porta", width=75, stretch=False)
tabela.column("status", width=125, stretch=False)
tabela.column("servico", width=155, stretch=False)
tabela.column("identificacao", width=245, stretch=False)
tabela.column("detalhes", width=360)
tabela.pack(fill="both", expand=True)

rotulo_status = ttk.Label(janela, text="Base OUI local inicial (parcial); filtros disponíveis. Execute 'Descobrir dispositivos'.", padding=10)
rotulo_status.pack(anchor="w")
atualizar_painel_seguranca()
atualizar_central_alertas()
janela.after(100, processar_resultados)
janela.mainloop()