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

_ShiftRows()_: Dịch vòng ba hàng cuối của mảng trạng thái
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
 Để hoàn thành nốt hàm _sub_bytes()_, mình chỉ cần thay thế giá trị trong state với giá trị trong bảng inv_s_box
<pre>
def sub_bytes(s, sbox=inv_s_box):
    result = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            byte = s[i][j]
            result[i][j] = sbox[byte]
    return result
</pre>
Sau khi có được ma trận mới, mình sẽ convert ma trận đó sang bytes là sẽ có được flag
![image](https://github.com/hoahangsau/trialAES/assets/153940762/90fa2ff5-9aca-4a73-bba4-7e3fe66a918c)

**Diffusion through Permutation**
Hàm _shift_rows()_ dịch các hàng của ma trận s sang trái. Cụ thể, nó dịch hàng đầu tiên 1 vị trí, hàng thứ hai 2 vị trí, và hàng thứ ba 3 vị trí. Hàng cuối cùng không bị dịch. Để hoàn thành hàm _inv_shift_rows()_, ta chỉ cần thực hiện ngược lại. 
<pre>
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]
</pre>
![Screenshot 2024-04-12 145311](https://github.com/hoahangsau/trialAES/assets/153940762/165ca2b6-30af-46fd-94c7-bb86d77de4bf)

**BringItAllTogether**


![image](https://github.com/hoahangsau/trialAES/assets/153940762/39c0898b-147f-4a17-8e46-3d4821fda105)

Dựa vào đoạn code đã cho và các bước để decrypt AES đã cho ở bức ảnh trên, ta có đoạn code sau để decrypt
<pre>
N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )


    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):          
            state[i][j] ^= round_key[i][j]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]

def inv_sub_bytes(s):
    for i in range(len(s)):
        for j in range(len(s[i])):
            s[i][j] = inv_s_box[s[i][j]]



def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)
    
def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    arr = [i for row in matrix for i in row]
    byte_arr = bytes(arr)
    return byte_arr

def decrypt(key, ciphertext):
    round_keys = expand_key(key)

    # Convert ciphertext to state matrix
    state = bytes2matrix(ciphertext)

    # Initial add round key step
    add_round_key(state, round_keys[N_ROUNDS])

    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Final round
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    # Convert state matrix to plaintext
    plaintext = matrix2bytes(state)
    return plaintext

print(decrypt(key, ciphertext))
</pre>

Để sinh khóa cho 10 vòng lặp, chúng ta sử dụng hàm _expand_key()_, các bước để sinh khóa đã được viết trong các comment. Đối với mỗi vòng lặp ta sẽ dùng các hàm inv_shift_rows(state),   inv_sub_bytes(state), add_round_key(state, round_keys[i]), inv_mix_columns(state) để giải mã. Riêng đối với vòng lặp cuối cùng sẽ không cần dùng đến inv_mix_columns.
![Screenshot 2024-04-12 170240](https://github.com/hoahangsau/trialAES/assets/153940762/e1ef3cb3-b1b7-4c05-991f-4179edf0ae4b)

**Modes of Operation Starter**
Nhìn vào dòng "@chal.route('/block_cipher_starter/encrypt_flag/')" mình gõ dòng này lên URL của page thì nhận được một đoạn ciphertext.
![image](https://github.com/hoahangsau/trialAES/assets/153940762/78549d18-170a-4242-8d49-2b0a420d438e)

Đưa dòng ciphertext này để decrypt ta sẽ thu được plaintext dạng hex như trong ảnh, sau đó đưa vào hex encoder sẽ ra được flag.
![image](https://github.com/hoahangsau/trialAES/assets/153940762/c3fa8b3f-7250-49ed-a1da-b65c72e15a84)

**Passwords as Keys**
Dựa vào đoạn code được cung cấp, ta sẽ thấy một dictionary key được lấy qua đường link: https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
Sau đó key được mã hóa md5 để encrypt AES.
Để có được key, chúng ta cần bruteforce từng password một, dưới đây là đoạn script để bruteforce
<pre>
from Crypto.Cipher import AES
import hashlib

import requests
url1 = "http://aes.cryptohack.org/passwords_as_keys/"
r = requests.get(f"{url1}/encrypt_flag")
data = r.json()
c = data["ciphertext"]
ciphertext = bytes.fromhex(c)
with open(r"C:\Users\hoaha\OneDrive\Máy tính\Training EHC\Cryptohack\SymmetricCryptography\bruteforce.txt") as f:
    words = [w.strip() for w in f.readlines()]
for i in words:
    key = hashlib.md5(i.encode()).digest()
    cipher = AES.new(key,AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    if b'crypto' in decrypted:
        print(decrypted)
</pre>
![image](https://github.com/hoahangsau/trialAES/assets/153940762/bacaf1db-2003-4176-8595-e538552ec020)

Để hoàn thành nốt hàm _sub_bytes()_, mình chỉ cần thay thế giá trị trong state với giá trị trong bảng inv_s_box
<pre>
def sub_bytes(s, sbox=inv_s_box):
    result = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            byte = s[i][j]
            result[i][j] = sbox[byte]
    return result
</pre>
Sau khi có được ma trận mới, mình sẽ convert ma trận đó sang bytes là sẽ có được flag
![image](https://github.com/hoahangsau/trialAES/assets/153940762/90fa2ff5-9aca-4a73-bba4-7e3fe66a918c)

**Diffusion through Permutation**
Hàm _shift_rows()_ dịch các hàng của ma trận s sang trái. Cụ thể, nó dịch hàng đầu tiên 1 vị trí, hàng thứ hai 2 vị trí, và hàng thứ ba 3 vị trí. Hàng cuối cùng không bị dịch. Để hoàn thành hàm _inv_shift_rows()_, ta chỉ cần thực hiện ngược lại. 
<pre>
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]
</pre>
![Screenshot 2024-04-12 145311](https://github.com/hoahangsau/trialAES/assets/153940762/165ca2b6-30af-46fd-94c7-bb86d77de4bf)

**BringItAllTogether**


![image](https://github.com/hoahangsau/trialAES/assets/153940762/39c0898b-147f-4a17-8e46-3d4821fda105)

Dựa vào đoạn code đã cho và các bước để decrypt AES đã cho ở bức ảnh trên, ta có đoạn code sau để decrypt
<pre>
N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )


    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):          
            state[i][j] ^= round_key[i][j]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]

def inv_sub_bytes(s):
    for i in range(len(s)):
        for j in range(len(s[i])):
            s[i][j] = inv_s_box[s[i][j]]



def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)
    
def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    arr = [i for row in matrix for i in row]
    byte_arr = bytes(arr)
    return byte_arr

def decrypt(key, ciphertext):
    round_keys = expand_key(key)

    # Convert ciphertext to state matrix
    state = bytes2matrix(ciphertext)

    # Initial add round key step
    add_round_key(state, round_keys[N_ROUNDS])

    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Final round
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    # Convert state matrix to plaintext
    plaintext = matrix2bytes(state)
    return plaintext

print(decrypt(key, ciphertext))
</pre>

Để sinh khóa cho 10 vòng lặp, chúng ta sử dụng hàm _expand_key()_, các bước để sinh khóa đã được viết trong các comment. Đối với mỗi vòng lặp ta sẽ dùng các hàm inv_shift_rows(state),   inv_sub_bytes(state), add_round_key(state, round_keys[i]), inv_mix_columns(state) để giải mã. Riêng đối với vòng lặp cuối cùng sẽ không cần dùng đến inv_mix_columns.
![Screenshot 2024-04-12 170240](https://github.com/hoahangsau/trialAES/assets/153940762/e1ef3cb3-b1b7-4c05-991f-4179edf0ae4b)

**Modes of Operation Starter**
Nhìn vào dòng "@chal.route('/block_cipher_starter/encrypt_flag/')" mình gõ dòng này lên URL của page thì nhận được một đoạn ciphertext.
![image](https://github.com/hoahangsau/trialAES/assets/153940762/78549d18-170a-4242-8d49-2b0a420d438e)

Đưa dòng ciphertext này để decrypt ta sẽ thu được plaintext dạng hex như trong ảnh, sau đó đưa vào hex encoder sẽ ra được flag.
![image](https://github.com/hoahangsau/trialAES/assets/153940762/c3fa8b3f-7250-49ed-a1da-b65c72e15a84)

**Passwords as Keys**
Dựa vào đoạn code được cung cấp, ta sẽ thấy một dictionary key được lấy qua đường link: https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words
Sau đó key được mã hóa md5 để encrypt AES.
Để có được key, chúng ta cần bruteforce từng password một, dưới đây là đoạn script để bruteforce
<pre>
from Crypto.Cipher import AES
import hashlib

import requests
url1 = "http://aes.cryptohack.org/passwords_as_keys/"
r = requests.get(f"{url1}/encrypt_flag")
data = r.json()
c = data["ciphertext"]
ciphertext = bytes.fromhex(c)
with open(r"C:\Users\hoaha\OneDrive\Máy tính\Training EHC\Cryptohack\SymmetricCryptography\bruteforce.txt") as f:
    words = [w.strip() for w in f.readlines()]
for i in words:
    key = hashlib.md5(i.encode()).digest()
    cipher = AES.new(key,AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    if b'crypto' in decrypted:
        print(decrypted)
</pre>
![image](https://github.com/hoahangsau/trialAES/assets/153940762/bacaf1db-2003-4176-8595-e538552ec020)

**ECB Oracle**












