#!/usr/bin/env python3
import socket, json, argparse, random, base64, logging
from Crypto.Cipher import AES

def send_json(s,o): s.sendall((json.dumps(o)+"\n").encode())
def recv_json(s):
    buf=b""
    while b"\n" not in buf:
        chunk=s.recv(4096)
        if not chunk: break
        buf+=chunk
    line,_=buf.split(b"\n",1)
    return json.loads(line.decode())

def is_prime(n):
    if n<2:return False
    if n%2==0:return n==2
    r=int(n**0.5);f=3
    while f<=r:
        if n%f==0:return False
        f+=2
    return True
def factorize(n):
    fac=[];d=2
    while d*d<=n:
        while n%d==0:fac.append(d);n//=d
        d+=1 if d==2 else 2
    if n>1:fac.append(n)
    return list(set(fac))
def is_generator(g,p):
    if not is_prime(p):return False
    phi=p-1
    for q in factorize(phi):
        if pow(g,phi//q,p)==1:return False
    return True
def derive_aes(secret):
    b2=secret.to_bytes(2,'big');return(b2*16)[:32]
def aes_enc_b64(msg,key):
    cipher=AES.new(key,AES.MODE_ECB)
    pad=16-(len(msg)%16)
    ct=cipher.encrypt(msg.encode()+bytes([pad])*pad)
    return base64.b64encode(ct).decode()
def aes_dec_b64(b64,key):
    cipher=AES.new(key,AES.MODE_ECB)
    ct=base64.b64decode(b64)
    pt=cipher.decrypt(ct)
    return pt[:-pt[-1]].decode()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("-a","--addr",required=True)
    ap.add_argument("-p","--port",type=int,required=True)
    ap.add_argument("-l","--log",default="INFO")
    args=ap.parse_args()
    logging.basicConfig(level=getattr(logging,args.log.upper(),logging.INFO),format="%(message)s")

    s=socket.create_connection((args.addr,args.port))
    send_json(s,{"opcode":0,"type":"DH"})
    msg=recv_json(s)

    p=msg["parameter"]["p"]; g=msg["parameter"]["g"]; B=msg["public"]
    logging.info(f"[Alice P3] Received from Bob → p={p}, g={g}, B={B}")

    if not is_prime(p):
        send_json(s,{"opcode":3,"error":"incorrect prime number"});return
    if not is_generator(g,p):
        send_json(s,{"opcode":3,"error":"incorrect generator"});return

    a=random.randint(2,p-2)
    A=pow(g,a,p)
    logging.info(f"[Alice P3] Private key a={a}")
    logging.info(f"[Alice P3] Public key A=g^a mod p={A}")
    send_json(s,{"opcode":1,"type":"DH","public":A})

    secret=pow(B,a,p)
    logging.info(f"[Alice P3] Shared secret (K = B^a mod p) = {secret}")

    key=derive_aes(secret)
    logging.info(f"[Alice P3] Derived AES key (len={len(key)} bytes)")


    enc=aes_enc_b64("hello",key)
    send_json(s,{"opcode":2,"type":"AES","encryption":enc})
    rep=recv_json(s)
    pt=aes_dec_b64(rep["encryption"],key)
    logging.info(f"[Alice P3] AES decrypted reply: {pt}")
    s.close()

if __name__=="__main__":
    main()
