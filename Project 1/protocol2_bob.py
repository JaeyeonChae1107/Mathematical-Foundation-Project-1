import socket
import threading
import argparse
import logging
import json
import base64
import random
from Crypto.Cipher import AES

# 패딩 및 제거
def pad(msg):
    pad_len = 16 - (len(msg) % 16)
    return msg + chr(pad_len) * pad_len

def unpad(msg):
    return msg[:-ord(msg[-1])]

# AES 암복호화 (ECB, Base64)
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext).encode())).decode()

def aes_decrypt(key, ciphertext_b64):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)).decode(errors="ignore"))

# 소수 판별 및 랜덤 소수 생성 (400-500 범위)
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_prime():
    while True:
        candidate = random.randint(400, 500)
        if is_prime(candidate):
            return candidate

# 모듈러 역원 (Python 3.7 호환)
def modinv(a, m):
    # 확장 유클리드로 a^{-1} mod m 계산
    def egcd(x, y):
        if y == 0:
            return (1, 0)
        else:
            q, r = divmod(x, y)
            s, t = egcd(y, r)
            return (t, s - q * t)
    inv, _ = egcd(a, m)
    return inv % m

# RSA per-byte 복호화 (정수 리스트 -> bytes)
def rsa_decrypt_list(enc_list, d, n):
    dec_bytes = bytearray()
    for c in enc_list:
        m = pow(c, d, n)
        dec_bytes.append(m)
    return bytes(dec_bytes)

# 클라이언트 연결 처리
def handler(sock, bob_msg):
    try:
        # RSA 요청 수신
        data = sock.recv(8192).decode().strip()
        if not data:
            sock.close()
            return
        req = json.loads(data)
        logging.info(f"Received: {req}")

        # RSA 키 생성 (매 세션마다 새로 생성)
        p, q = generate_prime(), generate_prime()
        while p == q:
            q = generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = modinv(e, phi)

        logging.info(f"Generated RSA keypair (p={p}, q={q}, n={n})")

        # RSA 요청 응답
        if req.get("type") in ("RSA", "RSAKey"):
            reply = {
                "opcode": 1,
                "type": "RSA",
                "public": e,
                "parameter": {"n": n}
            }
            sock.send(json.dumps(reply).encode())

        # AES 키 수신 (RSA per-byte 암호화된 리스트)
        data = sock.recv(8192).decode().strip()
        if not data:
            sock.close()
            return
        aes_msg = json.loads(data)
        if aes_msg.get("type") == "RSA" and "encrypted_key" in aes_msg:
            enc_list = aes_msg["encrypted_key"]
            aes_key = rsa_decrypt_list(enc_list, d, n)
            logging.info("AES key decrypted.")
        else:
            logging.warning("AES key message not received or unexpected format.")
            sock.close()
            return

        # AES 메시지 수신
        data = sock.recv(8192).decode().strip()
        if not data:
            sock.close()
            return
        msg = json.loads(data)
        if msg.get("type") == "AES" and "encryption" in msg:
            plaintext = aes_decrypt(aes_key, msg["encryption"])
            print(f"[Bob] Decrypted message: {plaintext}")

            # 응답 전송
            enc_response = aes_encrypt(aes_key, bob_msg)
            resp = {
                "opcode": 2,
                "type": "AES",
                "encryption": enc_response
            }
            sock.send(json.dumps(resp).encode())
            print(f"[Bob] Sent response: {bob_msg}")
        else:
            logging.warning("AES message not received or unexpected format.")

    except Exception as e:
        logging.error(f"Handler error: {e}")
    finally:
        sock.close()

# 서버 실행
def run(addr, port, bob_msg):
    s = socket.socket()
    s.bind((addr, port))
    s.listen(5)
    logging.info(f"[*] Bob listening on {addr}:{port}")
    while True:
        conn, info = s.accept()
        logging.info(f"[*] Connection from {info}")
        threading.Thread(target=handler, args=(conn, bob_msg)).start()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-a", "--addr", default="0.0.0.0")
    p.add_argument("-p", "--port", type=int, required=True)
    p.add_argument("-l", "--log", default="INFO")
    p.add_argument("-m", "--msg", type=str, default="Hello Alice!")
    a = p.parse_args()

    logging.basicConfig(level=getattr(logging, a.log.upper()))
    run(a.addr, a.port, a.msg)
