import sys
import os
import requests

def analyze_url(url, api_key):
    params = {
        'apikey': api_key,
        'resource': url
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    return response.json()

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 nome_do_script.py <arquivo.txt>")
        return
    
    file_path = sys.argv[1]
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    
    if api_key is None:
        print("Você precisa definir a api key do Virus total.")
        print("Certifique-se de configurar a variável de ambiente VIRUSTOTAL_API_KEY.")
        print("VIRUSTOTAL_API_KEY=SUA_API_KEY_VIrus_TOTAL")
        return
    
    try:
        with open(file_path, 'r') as file:
            urls = file.read().splitlines()
    except IOError:
        print(f"Não foi possível ler o arquivo: {file_path}")
        return
    
    for url in urls:
        result = analyze_url(url, api_key)
        
        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            print(f"\nAnálise para: {url}")
            print(f"Detecções: {positives}/{total}")
            
            scans = result['scans']
            print("\nDetalhes das verificações:")
            for scan, data in scans.items():
                print(f"{scan}: {data['result']}")
        else:
            print(f"\nAnálise para: {url}")
            print("URL não encontrada no VirusTotal.")

if __name__ == '__main__':
    main()
