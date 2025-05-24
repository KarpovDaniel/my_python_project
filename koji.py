import subprocess
import os
import json

def run_openssl_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Ошибка при выполнении команды openssl: {e.stderr}")

class KojiCertGenerator:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.ca_key_path = os.path.join(base_dir, 'koji_ca_cert.key')
        self.ca_cert_path = os.path.join(base_dir, 'koji_ca_cert.crt')
        self.certs_dir = os.path.join(base_dir, 'certs')
        self.csr_dir = os.path.join(base_dir, 'csr')
        self.permissions_file = os.path.join(base_dir, 'permissions.json')
        self.permissions = {}
        os.makedirs(self.certs_dir, exist_ok=True)
        os.makedirs(self.csr_dir, exist_ok=True)
        if os.path.exists(self.permissions_file):
            with open(self.permissions_file, 'r') as f:
                self.permissions = json.load(f)

    def generate_ca_cert(self, subject="/CN=Koji CA", days=3650):
        run_openssl_command(f"openssl genrsa -out {self.ca_key_path} 2048")
        run_openssl_command(
            f"openssl req -new -x509 -days {days} -key {self.ca_key_path} -out {self.ca_cert_path} -subj '{subject}'")

    def generate_cert(self, cn, auth, days):
        key_path = os.path.join(self.certs_dir, f"{cn}.key")
        csr_path = os.path.join(self.csr_dir, f"{cn}.csr")
        cert_path = os.path.join(self.certs_dir, f"{cn}.crt")
        ext_file = os.path.join(self.base_dir, "v3_ext.conf")

        # Генерация приватного ключа сервера
        run_openssl_command(f"openssl genrsa -out {key_path} 2048")
        # Генерация CSR для сервера
        run_openssl_command(f"openssl req -new -key {key_path} -out {csr_path} -subj '/CN={cn}'")
        # Создание файла конфигурации для расширений
        with open(ext_file, "w") as f:
            f.write(f"[v3_req]\nextendedKeyUsage = {auth}Auth")
        # Подпись CSR с помощью CA
        run_openssl_command(
            f"openssl x509 -req -in {csr_path} -CA {self.ca_cert_path} -CAkey {self.ca_key_path} -CAcreateserial -out {cert_path} -days {days} -extensions v3_req -extfile {ext_file}")
        # Удаление временного файла
        os.remove(ext_file)

    def generate_server_cert(self, cn, days=365):
        self.generate_cert(cn, "server", days)

    def generate_client_cert(self, cn, permissions=None, days=365):
        self.generate_cert(cn, "client", days)
        # Сохранение разрешений, если они указаны
        if permissions:
            self.assign_permissions(cn, permissions)

    def assign_permissions(self, cn, permissions):
        valid_permissions = {'admin', 'repo', 'build', 'tag', 'host', 'win-build', 'vm'}
        if not all(p in valid_permissions for p in permissions):
            raise ValueError(f"Недопустимые разрешения. Допустимые: {valid_permissions}")
        self.permissions[cn] = list(permissions)
        with open(self.permissions_file, 'w') as f:
            json.dump(self.permissions, f, indent=4)

    def get_permissions(self, cn):
        return self.permissions.get(cn, [])