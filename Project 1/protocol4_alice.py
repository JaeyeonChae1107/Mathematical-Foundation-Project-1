#!/usr/bin/env python3
import socket, json, argparse, logging

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

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("-a","--addr",required=True)
    ap.add_argument("-p","--port",type=int,required=True)
    ap.add_argument("-l","--log",default="INFO")
    args=ap.parse_args()
    logging.basicConfig(level=getattr(logging,args.log.upper(),logging.INFO))
    s=socket.create_connection((args.addr,args.port))
    send_json(s,{"opcode":0,"type":"DH"})
    msg=recv_json(s)
    p=msg["parameter"]["p"]; g=msg["parameter"]["g"]
    if not is_prime(p):
        send_json(s,{"opcode":3,"error":"incorrect prime number"})
        logging.info("[Alice P4] Sent error: incorrect prime number")
        return
    if not is_generator(g,p):
        send_json(s,{"opcode":3,"error":"incorrect generator"})
        logging.info("[Alice P4] Sent error: incorrect generator")
        return
    logging.info("[Alice P4] p,g valid – unexpected for Protocol IV.")
    s.close()

if __name__=="__main__":
    main()
