import socket, threading, argparse, logging, json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

def pad(msg): pad_len=16-(len(msg)%16); return msg+chr(pad_len)*pad_len
def unpad(msg): return msg[:-ord(msg[-1])]
def aes_encrypt(k,m): c=AES.new(k,AES.MODE_ECB); return base64.b64encode(c.encrypt(pad(m).encode())).decode()
def aes_decrypt(k,cipher): c=AES.new(k,AES.MODE_ECB); return unpad(c.decrypt(base64.b64decode(cipher)).decode(errors="ignore"))

def handler(sock, bob_msg):
    try:
        msg=json.loads(sock.recv(8192).decode())
        if msg["opcode"]==0 and msg["type"]=="RSAKey":
            key=RSA.generate(2048)
            pub=key.publickey().export_key().decode()
            sock.send(json.dumps({"opcode":1,"type":"RSA","public_key":pub}).encode())



            # Alice 메시지 복호화
            aes_msg=json.loads(sock.recv(8192).decode())
            alice_text=aes_decrypt(aes_key,aes_msg["encryption"])
            print(f"[Bob] Decrypted message from Alice: {alice_text}")

            # Bob 메시지 전송
            b64=aes_encrypt(aes_key,bob_msg)
            sock.send(json.dumps({"opcode":2,"type":"AES","encryption":b64}).encode())
            print(f"[Bob] Sent encrypted response: {bob_msg}")
    except Exception as e:
        logging.error(f"Handler error: {e}")
    finally:
        sock.close()

def run(addr,port,bob_msg):
    s=socket.socket(); s.bind((addr,port)); s.listen(5)
    logging.info(f"[*] Bob listening on {addr}:{port}")
    while True:
        conn,info=s.accept()
        logging.info(f"[*] Connection from {info}")
        threading.Thread(target=handler,args=(conn,bob_msg)).start()

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("-a","--addr",default="0.0.0.0")
    p.add_argument("-p","--port",type=int,required=True)
    p.add_argument("-l","--log",default="INFO")
    p.add_argument("-m","--msg",type=str,default="Hi Alice! (default)")
    a=p.parse_args()
    logging.basicConfig(level=getattr(logging,a.log.upper()))
    run(a.addr,a.port,a.msg)
