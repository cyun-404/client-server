# 서버에 정수를 전달한다.
# 사용자 인증이 가능하다.
from socket import *

port_number, ip_address = 18000, '127.0.0.1'
    # TCP 연결
s = socket(AF_INET, SOCK_STREAM)
if not s.connect((ip_address, port_number)):
    # 사용자 인증
    print("---------------------")
    user_id = input("ID: ")
    s.send(user_id.encode())
    user_pw = input("PW : ")
    s.send(user_pw.encode())
    print("-------------------")

    server_message = s.recv(1024)
    print(server_message.decode())

if server_message.decode() == '인증 실패!':
    exit()

#전달할 정수
message= input("제곱값이 궁금한 정수 : ")

# 서버에 정수 값을 전달
s.sendall(message.encode())
print(s.recv(1000).decode())
