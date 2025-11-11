import socket
import argparse
import logging
import json
import base64
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# 메시지 패딩
def pad(msg):
    pad_len = 16 - (len(msg) % 16)
    return msg + chr(pad_len) * pad_len

# 메시지 패딩 제거
def unpad(msg):
    return msg[:-ord(msg[-1])]

# AES 암호화 (ECB)
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext).encode())).decode()

# AES 복호화 (ECB)
def aes_decrypt(key, ciphertext_b64):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)).decode(errors="ignore"))

# RSA per-byte 암호화
def rsa_pow_list_per_byte(key_bytes, e, n):
    enc_list = []
    for b in key_bytes:
        c = pow(b, e, n)
        enc_list.append(c)
    return enc_list

# RSA 파라미터 핸드셰이크
def handshake_get_en(addr, port, log_wait=0.2):
    s = socket.socket()
    s.connect((addr, port))
    logging.info(f"Alice connected to {addr}:{port}")

    # 표준 요청: {"opcode":0,"type":"RSA"}
    s.send(json.dumps({"opcode": 0, "type": "RSA"}).encode())
    logging.info("Sent RSA (Protocol II) request.")
    time.sleep(log_wait)
    raw = s.recv(8192).decode().strip()
    logging.debug(f"Raw reply (RSA): {repr(raw)}")

    if raw:
        try:
            rep = json.loads(raw)
            if rep.get("type") == "RSA" and "public" in rep and "parameter" in rep and "n" in rep["parameter"]:
                e = rep["public"]
                n = rep["parameter"]["n"]
                return s, e, n
        except json.JSONDecodeError:
            pass

    # 변형 요청: {"opcode":0,"type":"RSAKey"}
    logging.info("Retrying with RSAKey (variant).")
    s.close()
    s = socket.socket()
    s.connect((addr, port))
    s.send(json.dumps({"opcode": 0, "type": "RSAKey"}).encode())
    logging.info("Sent RSAKey request (variant).")
    time.sleep(log_wait)
    raw2 = s.recv(8192).decode().strip()
    logging.debug(f"Raw reply (RSAKey): {repr(raw2)}")
    if not raw2:
        raise RuntimeError("No RSA parameters received from server.")

    rep2 = json.loads(raw2)
    if rep2.get("type") in ("RSAKey", "RSA") and "public" in rep2 and "parameter" in rep2:
        par = rep2["parameter"]
        if "n" in par:
            e = rep2["public"]
            n = par["n"]
            return s, e, n
        elif "p" in par and "q" in par:
            e = rep2["public"]
            n = par["p"] * par["q"]
            return s, e, n

    raise RuntimeError(f"Unrecognized RSA response: {rep2}")

# 전체 통신 절차
def run(addr, port, message):
    s, e, n = handshake_get_en(addr, port)
    logging.info(f"RSA parameters resolved: e={e}, n={n}")

    aes_key = get_random_bytes(32)
    enc_key_list = rsa_pow_list_per_byte(aes_key, e, n)

    rsa_key_packet = {
        "opcode": 2,
        "type": "RSA",
        "encrypted_key": enc_key_list
    }
    s.send(json.dumps(rsa_key_packet).encode())
    logging.info("Sent RSA-encrypted AES key (per-byte list).")

    enc_msg_b64 = aes_encrypt(aes_key, message)
    msg_packet = {
        "opcode": 2,
        "type": "AES",
        "encryption": enc_msg_b64
    }
    s.send(json.dumps(msg_packet).encode())
    logging.info("Sent AES-encrypted message.")

    raw = s.recv(8192).decode().strip()
    logging.debug(f"Raw encrypted reply: {repr(raw)}")
    if not raw:
        logging.error("No response received from server after AES message.")
        s.close()
        return

    rep = json.loads(raw)
    if rep.get("type") == "AES" and "encryption" in rep:
        try:
            plaintext = aes_decrypt(aes_key, rep["encryption"])
            print(f"[Alice] Decrypted response: {plaintext}")
        except Exception as ex:
            logging.error(f"AES decrypt failed: {ex}")
    else:
        logging.warning(f"Unexpected response format: {rep}")

    s.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True)
    ap.add_argument("-p", "--port", type=int, required=True)
    ap.add_argument("-l", "--log", default="INFO")
    ap.add_argument("-m", "--msg", type=str, default="hello")
    args = ap.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run(args.addr, args.port, args.msg)
