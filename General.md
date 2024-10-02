**#ASCII**
Mình sẽ sử dụng vòng lặp for và lệnh _chr_ để chuyển đổi các phần tử trong mảng thành ký tự ASCII
<pre>
  asciichar = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
for num in asciichar:
    print(chr(num), end='')
</pre>

  =>OUTPUT: crypto{ASCII_pr1nt4bl3}
![image](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/6f29e1f9-67c2-43e5-a325-a45dcff3a985)

**#Hex**
Mình sẽ sử dụng hàm <pre>bytes.fromhex()</pre> để chuyển đổi từ hex sang bytes
<pre>
  hex ="63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
flag = bytes.fromhex(hex)
print(flag)
</pre>
=>OUTPUT:b'crypto{You_will_be_working_with_hex_strings_a_lot}'
![Screenshot 2024-02-23 142225](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/4dc34072-d512-4ff8-b0dc-d73ee5f52032)

**#Base64**
Trước tiên phải import thư viện base64, sau đó decode đoạn hex thành bytes và encode sang base64 bằng hàm <pre>base64.b64encode()</pre>
<pre>
  import base64
hex ="72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
bytes = bytes.fromhex(hex)
flag = base64.b64encode(bytes)
print(flag)
</pre>
![Screenshot 2024-02-23 144848](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/f75f3306-e21e-4156-bf62-a269cc9e0775)

**#BytesAndBigIntegers**
Sau khi install pycryptodome thì chúng ta có thể import được các method bytes_to_long() và long_to_bytes()
<pre>long_to_bytes() : chuyển đổi từ số nguyên dạng long sang chuỗi bytes, còn bytes_to_long() thì ngược lại</pre>
<pre>
  from Crypto.Util.number import long_to_bytes
long = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
bytes = long_to_bytes(long)
print(bytes)
</pre>
![Screenshot 2024-02-23 162732](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/567d8deb-d466-441d-9e7b-cdb5a793687d)

**#XORStarter**
Để XOR với một chữ thì ta phải chuyển đổi chữ đó tương ứng với số trong bảng mã ASCII trước bằng lệnh _ord_
<pre>
  string ="label"
for char in string:
    result1=ord(char)^13
    result2=chr(result1)
    print(result2,end='')
</pre>
![image](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/0c8ede1a-ad1a-452a-84c5-32847f926e72)

**#XORProperties**
XOR có tính chất đối xứng nên chúng ta có thể tìm được các KEY từ dữ liệu đề bài
<pre>
  Example: A ^ B = C <=> C ^ B = A
</pre>
Trước khi XOR thì chúng ta phải decode các hex key sang bytes
<pre>
  from Crypto.Util.number import long_to_bytes, bytes_to_long 

KEY1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY12 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
KEY23 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
KEYALL = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

KEY2 = bytes_to_long(bytes.fromhex(KEY1)) ^ bytes_to_long(bytes.fromhex(KEY12))
KEY3 = KEY2 ^ bytes_to_long(bytes.fromhex(KEY23))
FLAG = bytes_to_long(bytes.fromhex(KEYALL)) ^ KEY3 ^ KEY2 ^ bytes_to_long(bytes.fromhex(KEY1))
flag = long_to_bytes(FLAG)
print(flag)
</pre>
![image](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/2e520d29-d70b-4947-835d-287a4471ca78)

**#FavouriteByte**
Đối với bài này ta sẽ phải XOR với từng byte. Mỗi byte có thể có giá trị từ 0 đến 255.
<Pre>
  hex="73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
byte = bytes.fromhex(hex)
for num in range(256):   
    results = [chr(n^num) for n in byte]
    flag = "".join(results)   
    if flag.startswith('crypto'):
        print(flag)
</Pre>
![Screenshot 2024-02-24 151342](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/cbdecca9-18cd-4ab1-9cb3-6ecd1f127713)

**#You either know, XOR you don't**
Vì mình đã biết format flag là "crypto{...}" nên chúng ta có thể tận dụng để làm XOR key, sau khi xor lần một thì thấy được thêm XOR key nữa, nếu ta tiếp tục XOR lần hai với XOR key đó sẽ ra được flag
<Pre>
  from pwn import xor 
hex="0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
byte=bytes.fromhex(hex)
key1=xor(byte,"crypto{")
flag=xor(byte,"myXORkey")
print(flag)
</Pre>
![Screenshot 2024-02-24 152630](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/7bff5185-2dec-4351-85d3-20e6135d9b5b)

**#LemurXOR**
Trong thử thách này, mình sẽ làm việc với thư viện Pillow(PIL). Trước tiên dùng method _subtract_ từ module _ImageChops_ để tìm ra các giá trị pixel khác biệt giữa hai bức ảnh, sau đó combine các giá trị đó lại sẽ ra được bức ảnh chứa flag.
<Pre>
from PIL import Image, ImageChops
image1 = Image.open("lemur.png")
image2 = Image.open("flag.png")
image3 = ImageChops.add(ImageChops.subtract(image2, image1), ImageChops.subtract(image1, image2))
image3.show()
</Pre>
![image](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/269ce55f-a9a4-4a82-8808-68619b4a1d32)

**#GCD**
Mình sử dụng thuật toán Euclid để tìm ra GCD
<pre>
  def gcd(a, b):
    while b:
       a,b=b,a%b
    return a
result=gcd(66528,52920)
print(result)
</pre>
![image](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/cffdba3c-e587-4581-ab0f-30e21900e823)

**#ExtendedGCD**
Mình áp dụng thuật toán Euclid mở rộng để tìm ra GCD,u,v sao cho 26513 * x + 32321 * y = gcd
<pre>
  def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)

print(extended_gcd(26513,32321))
</pre>
![Screenshot 2024-02-24 194957](https://github.com/hoahangsau/CryptohackChallenge/assets/153940762/2de568c7-4e42-464e-9194-4c5667ffadc5)
