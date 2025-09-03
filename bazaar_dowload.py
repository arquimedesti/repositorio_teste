import requests
import sys
import argparse
import pyzipper

SIZE = 2000 #coloque a quantidade de arquivos que deseja baixar
PATH = "../Full_hashes.txt" #coloque o caminho do arquivo

def check_sha256(s):
    if len(s) != 64:
        raise argparse.ArgumentTypeError(f"Invalid SHA-256 hash: {s}")
    return s

def request_malware_bazaar(data, headers):
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.HTTPError as http_err:
        print(f"[ERROR] HTTP error occurred: {http_err} - {response.text}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API request failed: {e}")
        sys.exit(1)

def extract_zip(file_name, password):
    try:
        with pyzipper.AESZipFile(file_name) as zf:
            zf.pwd = password
            zf.extractall(".")
            print(f"Sample '{file_name}' extracted successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to extract ZIP: {e}")
        sys.exit(1)
        
def load_hashes_from_file(path):
    with open(path, "r") as f:
        content = f.read()

    # Remove colchetes e quebras de linha desnecessárias
    content = content.strip().lstrip("[").rstrip("]")

    # Divide em elementos (cada hash entre aspas)
    hashes = [line.strip().strip('"') for line in content.splitlines() if line.strip()]

    return hashes


def main():
    parser = argparse.ArgumentParser(description='Download malware samples from Malware Bazaar')
    
    txt = load_hashes_from_file(PATH)
    
    hashes = txt[:SIZE]

    parser.add_argument('-s', '--hashes', nargs='+', default=hashes, type=check_sha256, help='List of SHA-256 hashes')

    parser.add_argument('-u', '--unzip', action='store_true', help='Unzip the downloaded files')
    parser.add_argument('-i', '--info', action='store_true', help='Get file information (no download)')
    args = parser.parse_args()

    if args.unzip and args.info:
        print("[ERROR] Please select either unzip or information display, not both.")
        sys.exit(1)

    API_KEY = "23680844bf6203c6ddd7354b4cff8cf7d078a43a296434c2" # coloque sua chave de API aqui
    headers = {
        'Auth-Key': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    ZIP_PASSWORD = b'infected'

    for sha_hash in args.hashes:
        if args.info:
            data = {'query': 'get_info', 'hash': sha_hash}
            response = request_malware_bazaar(data, headers)
            print(response.content.decode("utf-8", "ignore"))
        else:
            data = {'query': 'get_file', 'sha256_hash': sha_hash}
            response = request_malware_bazaar(data, headers)

            if 'file_not_found' in response.text:
                print(f"[ERROR] File not found: {sha_hash}")
                continue

            file_name = sha_hash + '.zip'
            with open(file_name, 'wb') as f:
                f.write(response.content)
            print(f"Sample '{sha_hash}' downloaded.")

            if args.unzip:
                extract_zip(file_name, ZIP_PASSWORD)

if __name__ == "__main__":
    #sys.argv.append('-u')  # Simula a passagem do argumento "-u" # Essa nao precisa ser executada porque o programa pega as dados do arquivo txt informado acima em path.
    main()
