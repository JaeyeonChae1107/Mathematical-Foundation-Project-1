import socket
import threading
import argparse
import logging
import json
import base64
from Crypto.Cipher import AES

# 메시지 패딩
def pad(msg):
    pad_len = 16 - (len(msg) % 16)
    return msg + chr(pad_len) * pad_len

# 패딩 제거
def unpad(msg):
    return msg[:-ord(msg[-1])]

# AES 암호화
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext).encode())).decode()

# AES 복호화
def aes_decrypt(key, ciphertext_b64):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)).decode(errors="ignore"))

# RSA per-byte 복호화
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

        # RSA 키 생성
        p, q = 457, 449
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537

        # d 계산 (확장 유클리드)
        def egcd(a, b):
            if b == 0:
                return (1, 0)
            else:
                x, y = egcd(b, a % b)
                return (y, x - (a // b) * y)
        d = egcd(e, phi)[0] % phi

        # RSA 요청 응답
        if req.get("type") in ("RSA", "RSAKey"):
            reply = {
                "opcode": 1,
                "type": "RSA",
                "public": e,
                "parameter": {"n": n}
            }
            sock.send(json.dumps(reply).encode())

        # AES 키 수신
        data = sock.recv(8192).decode().strip()
        if not data:
            sock.close()
            return
        aes_msg = json.loads(data)
        if aes_msg.get("type") == "RSA" and "encrypted_key" in aes_msg:
            enc_list = aes_msg["encrypted_key"]
            aes_key = rsa_decrypt_list(enc_list, d, n)
            logging.info("AES key decrypted.")

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
