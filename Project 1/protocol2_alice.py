import socket, argparse, logging, json, os, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

def pad(msg): pad_len=16-(len(msg)%16); return msg+chr(pad_len)*pad_len
def unpad(msg): return msg[:-ord(msg[-1])]
def aes_encrypt(k,m): c=AES.new(k,AES.MODE_ECB); return base64.b64encode(c.encrypt(pad(m).encode())).decode()
def aes_decrypt(k,cipher): c=AES.new(k,AES.MODE_ECB); return unpad(c.decrypt(base64.b64decode(cipher)).decode(errors="ignore"))

def run(addr,port,alice_msg):
    s=socket.socket(); s.connect((addr,port))
    logging.info(f"Alice connected to {addr}:{port}")

    # RSA 요청 및 공개키 수신
    s.send(json.dumps({"opcode":0,"type":"RSAKey"}).encode())
    reply=json.loads(s.recv(8192).decode())
    pubkey_pem=reply["public_key"]
    pubkey=RSA.import_key(pubkey_pem)
    logging.info("[>] Received RSA public key.")



    # Alice 메시지 전송
    b64=aes_encrypt(aes_key,alice_msg)
    s.send(json.dumps({"opcode":2,"type":"AES","encryption":b64}).encode())
    print(f"[Alice] Sent encrypted: {b64}")

    # Bob 응답 수신
    data=s.recv(8192).decode()
    if data:
        rep=json.loads(data)
        plaintext=aes_decrypt(aes_key,rep["encryption"])
        print(f"[Alice] Decrypted response: {plaintext}")

    s.close()

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("-a","--addr",required=True)
    p.add_argument("-p","--port",type=int,required=True)
    p.add_argument("-l","--log",default="INFO")
    p.add_argument("-m","--msg",type=str,default="Hi Bob! (default)")
    a=p.parse_args()
    logging.basicConfig(level=getattr(logging,a.log.upper()))
    run(a.addr,a.port,a.msg)
