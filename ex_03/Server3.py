# diffe-hellman 알고리즘을 통해 비밀키를 만들어 정보를 주고받는다.
# Client에게 제곱값을 반환시켜준다.
# 사용자 인증이 가능하다.
# 대칭키 암호화 방식으로 DES 방식을 채택한다.
from socket import *
from Crypto.Cipher import DES

def diffe_key(client_data):
    # 공개키
    p = 221185 
    g = 1340

    # 임의의 정수 b
    b = 12
    B = g**b % p

    # 앨리스에게 전송
    client_data.send(B.to_bytes(8,'big'))

    # 앨리스에게서 A를 전송받는다.
    A_bytes = client_data.recv(1024)
    A = int.from_bytes(A_bytes, 'big')
    s = A**b % p
    return s.to_bytes(8,'big')

# TCP 연결, 9000포트
port_number = 9000
s = socket(AF_INET,SOCK_STREAM)
s.bind(('172.16.11.2',port_number))
s.listen(1)


while True:
    trust = False

    # 클라이언트 연결
    clientData,addr = s.accept()
    print('다음 클라이언트가 연결됩니다. ',addr)
    
    # 대칭키 암호화
    key = diffe_key(clientData)
    des = DES.new(key, DES.MODE_ECB)

    # 암호화된 사용자 인증
    user_id = clientData.recv(1024)
    user_pw = clientData.recv(1024)

    decoded_id = des.decrypt(user_id).decode().rstrip()
    decoded_pass = des.decrypt(user_pw).decode().rstrip()

    with open('pw.txt',"r") as f:
        pw_id = f.readline().rstrip()
        pw_pass = f.readline().rstrip()

        if pw_id != decoded_id or pw_pass != decoded_pass:
            clientData.send("인증 실패!".encode())
        else:
            clientData.send("인증 성공!".encode())
            trust = True

    # 제곱값을 반환하는 서버
    while trust:
        data = clientData.recv(1024)
        if not data:
            break
        decoded_data = des.decrypt(data).decode().rstrip()
        pow_number = decoded_data + "의 제곱값은 " \
                    + str(int(decoded_data)*int(decoded_data)) + "입니다."
        clientData.sendall(pow_number.encode())
