# diffe-hellman 알고리즘으로 암호화하여 정보를 주고 받는다.
# 서버에 정수를 전달한다.
# 사용자 인증이 가능하다.
# DES 암호화를 통해 사용자 정보를 전달한다.
from socket import *
from Crypto.Cipher import DES

def diffe_key(socket):
    # 공개키
    g = 221185 
    p = 1340

    # 임의의 정수 a
    a = 321
    A = g**a % p

    # 밥에게 전송
    socket.send(A.to_bytes(8,'big'))

    # 밥에게서 B를 전송받는다.
    B_bytes = socket.recv(1024)
    B = int.from_bytes(B_bytes, 'big')
    s = B**a % p
    return s.to_bytes(8,'big')


# block size = 8
def pad(text):
    while len(text) % 8 != 0:
        text += ' '.encode()
    return text

# TCP 연결
s = socket(AF_INET, SOCK_STREAM)
port_number, ip_address = 9000, '172.16.11.2'



if not s.connect((ip_address, port_number)):
    # diffe-hellman 알고리즘을 사용한 des 키
    key = diffe_key(s)
    des = DES.new(key, DES.MODE_ECB)

    # 사용자 인증
    print("---------------------")
    user_id = input("ID: ")
    padded_id = pad(user_id.encode())
    encrypted_id = des.encrypt(padded_id) 
    s.send(encrypted_id)

    user_pw = input("PW : ")
    padded_pw = pad(user_pw.encode())
    encrypted_pw = des.encrypt(padded_pw) 
    s.send(encrypted_pw)
    print("---------------------")

    server_message = s.recv(1024)
    print(server_message.decode())

if server_message.decode() == '인증 실패!':
    exit()

#전달할 정수
message= input("제곱할 정수 : ")
padded_m = pad(message.encode())
encrypted_m = des.encrypt(padded_m)
# 서버에 정수 값을 전달
s.sendall(encrypted_m)
print(s.recv(1000).decode())
