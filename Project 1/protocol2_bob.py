import socket, threading, argparse, logging, json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

def pad(msg):
    pad_len = 16 - (len(msg) % 16)
    return msg + chr(pad_len) * pad_len

def unpad(msg):
    return msg[:-ord(msg[-1])]

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(enc).decode()

def aes_decrypt(key, b64_cipher):
    cipher = AES.new(key, AES.MODE_ECB)
    data = base64.b64decode(b64_cipher)
    dec = cipher.decrypt(data).decode(errors="ignore")
    return unpad(dec)

def handler(sock):
    try:
        # 1️⃣ Alice 요청 수신
        msg = json.loads(sock.recv(8192).decode())
        if msg["opcode"] == 0 and msg["type"] == "RSAKey":
            # RSA 키 생성
            key = RSA.generate(2048)
            pubkey_pem = key.publickey().export_key().decode()
            sock.sendall(json.dumps({
                "opcode": 1, "type": "RSA", "public_key": pubkey_pem
            }).encode())

            # 2️⃣ AES 키 수신
            enc_msg = json.loads(sock.recv(8192).decode())
            enc_key_b64 = enc_msg["encrypted_key"]
            enc_key = base64.b64decode(enc_key_b64)
            rsa_cipher = PKCS1_OAEP.new(key)
            aes_key = rsa_cipher.decrypt(enc_key)
            logging.info("[+] AES key received and decrypted.")

            # 3️⃣ AES 메시지 수신 및 복호화
            aes_msg = json.loads(sock.recv(8192).decode())
            plaintext = aes_decrypt(aes_key, aes_msg["encryption"])
            print(f"[Bob] Decrypted message: {plaintext}")

            # 4️⃣ 응답 전송
            b64_enc = aes_encrypt(aes_key, "world")
            sock.sendall(json.dumps({
                "opcode": 2, "type": "AES", "encryption": b64_enc
            }).encode())
            print("[Bob] Sent encrypted response.")

    except Exception as e:
        logging.error(f"Handler error: {e}")
    finally:
        sock.close()

def run(addr, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr, port))
    server.listen(5)
    logging.info(f"[*] Bob listening on {addr}:{port}")
    while True:
        conn, info = server.accept()
        logging.info(f"[*] Connection from {info}")
        threading.Thread(target=handler, args=(conn,)).start()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-a","--addr",default="0.0.0.0")
    p.add_argument("-p","--port",type=int,required=True)
    p.add_argument("-l","--log",default="INFO")
    a = p.parse_args()
    logging.basicConfig(level=getattr(logging,a.log.upper()))
    run(a.addr,a.port)
