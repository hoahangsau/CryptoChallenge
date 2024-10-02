**#Finding Flags** 
Đối với challenge này thì mình chỉ cần copy paste đoạn flag đã cho là được 
![image](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/529cd6d9-234e-48fb-8a1b-a3483c67f224)


**#Great Snakes**
Sau khi chạy đoạn code thì chúng ta sẽ nhận được flag. Đoạn code sẽ XOR các số trong mảng với giá trị 0x32(50), sau đó dùng lệnh _chr_ để chuyển đổi các số trong mảng sang ký tự ASCII tương ứng (còn lệnh _ord()_ có tác dụng ngược lại) rồi nối tất cả các ký tự với nhau bằng lệnh _join_
![Screenshot 2024-02-23 000137](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/6b2aaab4-ce17-4fc4-88d3-02d411c3d558)


**#Network Attacks**
**_Cách 1_**
Kết nối tới sever bằng lệnh _nc socket.cryptohack.org 11112_. Sau đó gửi một JSON object với key "buy" và value "flag" mà đề bài cho (**JSON là một định dạng phổ biến trong việc truyền tải dữ liệu qua mạng**)
![Screenshot 2024-02-23 002256](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/fdb2dd4d-aeaa-40fd-816b-af061fd33db7)

**_Cách 2_**
<pre>
  import socket
import json

HOST = "socket.cryptohack.org"
PORT = 11112

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
r.connect((HOST, PORT))

def readline():
    data = b""
    while True:
        char = r.recv(1)
        if char == b"\n":
            break
        data += char
    return data.decode()

def json_recv():
    line = readline()
    return json.loads(line)

def json_send(hsh):
    request = json.dumps(hsh).encode() 
    r.sendall(request)

try:
    for i in range(4):
        print(readline())


    request = {"buy": "flag"}
    json_send(request)


    response = json_recv()
    print(response)

finally:
    r.close()
</pre>

Đoạn script trên thiết lập kết nối với sever socket, sử dụng các hàm readline(), json_recv(), json_send() để gửi data, nhận data và đọc data từ sever.
