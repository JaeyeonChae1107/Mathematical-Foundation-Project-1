import socket, argparse, logging, json, os, base64
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

def run(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    logging.info(f"Alice connected to {addr}:{port}")

    # 1️⃣ RSA 공개키 요청
    s.send(json.dumps({"opcode":0,"type":"RSAKey"}).encode())
    reply = json.loads(s.recv(8192).decode())
    pubkey_pem = reply["public_key"]
    pubkey = RSA.import_key(pubkey_pem)
    logging.info("[>] Received RSA public key.")

    # 2️⃣ AES 키 생성 후 암호화
    aes_key = os.urandom(32)
    rsa_cipher = PKCS1_OAEP.new(pubkey)
    enc_key = rsa_cipher.encrypt(aes_key)
    enc_key_b64 = base64.b64encode(enc_key).decode()
    s.send(json.dumps({
        "opcode": 2, "type": "RSA", "encrypted_key": enc_key_b64
    }).encode())
    logging.info("[>] Sent encrypted AES key.")

    # 3️⃣ “hello” 전송
    b64_enc = aes_encrypt(aes_key, "hello")
    s.send(json.dumps({
        "opcode": 2, "type": "AES", "encryption": b64_enc
    }).encode())
    print(f"[Alice] Sent encrypted: {b64_enc}")

    # 4️⃣ Bob의 응답 수신
    data = s.recv(8192).decode()
    if data:
        reply = json.loads(data)
        decrypted = aes_decrypt(aes_key, reply["encryption"])
        print(f"[Alice] Decrypted response: {decrypted}")

    s.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-a","--addr",required=True)
    p.add_argument("-p","--port",type=int,required=True)
    p.add_argument("-l","--log",default="INFO")
    a = p.parse_args()
    logging.basicConfig(level=getattr(logging,a.log.upper()))
    run(a.addr,a.port)
