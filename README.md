# Dockerfile para produção

FROM kalilinux/kali-rolling

# Atualiza o sistema e instala dependências essenciais
```
RUN apt-get update && apt-get install -y \
    python3 python3-pip nmap metasploit-framework \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
```
# Instala bibliotecas Python necessárias
```
RUN pip3 install --no-cache-dir python-nmap metasploit.msfrpc
```
# Copia o script para dentro do container
```
COPY vulnscanner.py /opt/vulnscanner.py
```
# Define a senha do Metasploit RPC via variável de ambiente para segurança
```
ENV MSF_PASSWORD=your_secure_password_here
```
# Exponha a porta do Metasploit RPC
```
EXPOSE 55553
```
# Comando para iniciar o Metasploit RPC e depois o script Python
```
CMD msfrpcd -P $MSF_PASSWORD -S -a 0.0.0.0 -p 55553 & \
    sleep 10 && \
    python3 /opt/vulnscanner.py
```
### Instruções para produção
```
    Altere your_secure_password_here no Dockerfile para uma senha forte.
```
### Construa a imagem:
```
docker build -t vulnscannerpro:prod .
```
### Rode o container, mapeando a porta 55553 para o host:
```
docker run -it --rm -p 55553:55553 vulnscannerpro:prod
```

docker run -it --rm -p 55553:55553 vulnscannerpro:prod
```
docker run -it --rm -p 55553:55553 vulnscannerpro:prod
```
Quando o script pedir, informe o alvo e a mesma senha configurada no Dockerfile.
