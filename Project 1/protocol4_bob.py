#!/usr/bin/env python3
import socket, json, argparse, random, logging

def send_json(c,o): c.sendall((json.dumps(o)+"\n").encode())
def recv_json(c):
    buf=b""
    while b"\n" not in buf:
        chunk=c.recv(4096)
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
def pick_prime_400_500():
    while True:
        n=random.randint(400,500)
        if is_prime(n):return n

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=["dh-bad-prime","dh-bad-generator"],required=True)
    ap.add_argument("-a","--addr",default="0.0.0.0")
    ap.add_argument("-p","--port",type=int,required=True)
    ap.add_argument("-l","--log",default="INFO")
    args=ap.parse_args()
    logging.basicConfig(level=getattr(logging,args.log.upper(),logging.INFO))
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((args.addr,args.port)); s.listen(1)
    logging.info(f"[Bob P4] Listening mode={args.mode}")
    c,a=s.accept()
    req=recv_json(c)
    if args.mode=="dh-bad-prime":
        p=498; g=5
    else:
        p=pick_prime_400_500(); g=2
    b=random.randint(2,p-2); B=pow(g,b,p)
    send_json(c,{"opcode":1,"type":"DH","public":B,"parameter":{"p":p,"g":g}})
    try:
        r=recv_json(c)
        logging.info(f"[Bob P4] Received from Alice: {r}")
    except: pass
    c.close(); s.close()

if __name__=="__main__":
    main()
