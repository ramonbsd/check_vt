# check_vt
Script Python que utiliza a API do VirusTotal para analisar URLs/IPs

# VirusTotal URL Analyzer

Este é um script Python que utiliza a API do VirusTotal para analisar URLs. Ele permite verificar se uma URL possui detecções de malware ou outros problemas de segurança, fornecendo detalhes das verificações realizadas por vários antivírus e mecanismos de segurança.

## Pré-requisitos

- Python 3.x
- Chave de API do VirusTotal

## Instalação

1. Clone este repositório para o seu ambiente local:
git clone https://github.com/ramonbsd/check_vt.git


2. Instale as dependências necessárias usando o gerenciador de pacotes `pip`:
pip install -r requirements.txt ( Nenhuma até o momento desde update)




## Uso

Execute o script fornecendo a URL como argumento da linha de comando:
python3 check_vt.py <URL> <Arquivo-Lista>



Certifique-se de definir a variável de ambiente `VIRUSTOTAL_API_KEY` com a sua chave de API do VirusTotal antes de executar o script.

## Contribuição

Contribuições são bem-vindas! Se você encontrar algum problema, tiver sugestões ou quiser adicionar recursos extras, sinta-se à vontade para abrir uma nova issue ou enviar um pull request.

## Licença

Este projeto é licenciado sob a licença : Em analise.



