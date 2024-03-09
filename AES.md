**Keyed Permutations**
AES sử dụng một phép hoán vị gọi lại bijection(one-to-one correspondence) để thực hiện mã hóa. Cụ thể hơn là các khối dữ liệu đầu vào được ánh xạ one-to-one để cho dữ liệu đầu ra. Dưới đây là một ví dụ cơ bản về bijection trong toán học nói chung.
![image](https://github.com/hoahangsau/Week3/assets/153940762/e02834c1-06af-444c-9d62-00a6363d6852)

**Resisting Bruteforce**
Biclique Attack được sử dụng để thực hiện tìm kiếm key.
Theo như thông tin mình tìm hiểu sơ qua thì Biclique Attack hoạt động như sau:

1.Có một cặp plaintext-ciphertext (P1, C1) và (P2, C2) tạo ra cùng các trạng thái khi được mã hóa.

2.Biclique được xây dựng để tạo ra các trạng thái từ nhiều cặp khác nhau (P3, C3), (P4, C4),....

3.Thực hiện brute-force trên các giá trị khóa trong khoảng biclique để tìm ra khóa đúng.

**Structure of AES**
- Một số khái niệm mới: 
_S-Box_
![image](https://github.com/hoahangsau/Week3/assets/153940762/f3fcad06-3f89-4b47-995d-41e534420a9c)
Ví dụ: ô 19 tương ứng với hàng 1 cột 9 => d4
       a0 tương ứng với hàng a cột 0 => e0
_SubBytes()_: thực hiện phép thay thế các byte của mảng trạng thái bằng cách sử dụng S-box ( như mình đã làm ví dụ ở bức ảnh trên )

_ShiftRows(): Dịch vòng ba hàng cuối của mảng trạng thái
![image](https://github.com/hoahangsau/Week3/assets/153940762/e6723052-4740-4256-a23d-7f6d59c2cf01)

_MixColumns_: Nhân mỗi cột của mảng trạng thái với các phần tử tương ứng trong hàng của trường GF(2^8)
![image](https://github.com/hoahangsau/Week3/assets/153940762/5d761019-8e4a-4f1d-b1c5-81d6ceab3893)

_AddRoundKey()_: Round Key sẽ được đưa vào mảng trạng thái bằng cách XOR bit.
![image](https://github.com/hoahangsau/Week3/assets/153940762/35be1dc5-4716-4f26-b2b3-5e203380ded1)

-Solution: Mình chỉ cần convert các phần tử trong matrix sang các ký tự bảng mã ASCII  
<pre>
  def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    arr = [chr(i) for rows in matrix for i in rows]
    flag = ''.join(arr)
    return flag
</pre>
![Screenshot 2024-03-09 181105](https://github.com/hoahangsau/Week3/assets/153940762/423b9a0d-57c3-4e37-a481-dd3ea950c122)

**Round Keys**
Để AddRoundKey, chúng ta sẽ xor từng phần tử của state và roundkey với nhau. Sau đó dùng hàm matrix2byte đã làm trước đó để in ra flag

<pre>
  def add_round_key(s, k):
    result = [[0 for _ in range(4)] for _ in range(4)]  
    for i in range(4):
        for j in range(4):          
            result[i][j] = state[i][j] ^ round_key[i][j]

    return result  

result = [[99, 114, 121, 112], [116, 111, 123, 114], [48, 117, 110, 100], [107, 51, 121, 125]]

def matrix2bytes(result):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    arr = [chr(i) for rows in result for i in rows]
    flag = ''.join(arr)
    return flag
</pre>

![Screenshot 2024-03-09 185704](https://github.com/hoahangsau/Week3/assets/153940762/2798f5e2-8f7c-41bb-b207-5d89a0fd1734)

**Confusion through Substitution**
-Thêm khái niệm mới 

_Subbyte()_: Biến đổi 4 bytes đầu vào thành 4 bytes đầu ra bằng cách sử dụng S-box lên từng byte

Ví dụ: 
<pre>Subbyte(73744765) sẽ cho ra out put là 8f92a0d bằng cách tra bảng S-box</pre>

_RotWord()_: thực hiện hoán vị một vòng doubleword và trả về kết quả là một doubleword 

Ví dụ:
<pre> RotWord(3c4fcf09) = 093c4fcf </pre>

_RCON_: Mảng chứa hằng số sử dụng trong các vòng lặp

RCON[i] chứa các giá trị nhận được bởi {02}^(i-1), {00}, {00}, {00}. Bảng RCON này sẽ được dùng để sinh khóa con trong vòng lặp
![image](https://github.com/hoahangsau/Week3/assets/153940762/03eb836e-d891-452d-9f38-2cae9a0e5abe)

-Từ các khái niệm trên, ta có thể hiểu được quá trình sinh khóa hoạt động như nào theo biểu đồ dưới đây
![image](https://github.com/hoahangsau/Week3/assets/153940762/23b79829-2abd-4732-a2e6-bd912422c992)

 *Số vòng lặp sẽ thay đổi tương ứng như sau: 10,12,14 vòng lặp với từng loại 128,192,256

