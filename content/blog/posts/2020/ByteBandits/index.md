+++
title="ByteBandits CTF 2020"
date=2020-04-13
path="2020/bytebanditsctf"
[extra]
tag="CTF Writeup"
+++

The challenges were good and really fun to solve, our team `7SecCTF` managed to solve 6 challenges.
## The `gremline` challenge was particularly interesting
---
It was a `Reverse-Engineering` Challenge.\
The challenge Description was :
```c
There's a gremlin in my machinery. I guess it'll stop working soon. Can you help me?
```
along with a file `cpg.bin` to download\
A Hint was also provided\
```rust
u32 table[10][2] = { {0xff, 1}, {0xfe, 2}, {0xfd, 3}, 
{0xfc, 4}, {0xfb, 5}, {0x00, 5}, {0x01, 4}, {0x02, 3}, {0x03, 2}, {0x04, 1} };
```
I downloaded the `cpg.bin` file.
```rust
grimline >> head cpg.bin
H:2,blockSize:1000,created:17168fe53f5,format:1,fletcher:a504a51d
H:2,blockSize:1000,created:17168fe53f5,format:1,fletcher:a504a51d
chunk:1,block:2,len:1,map:2,max:380,next:3,pages:3,root:400000c388,time:3ee,version:1  
�RSTU'��LANGUAGE��C��6)��FULL_NAME��<global>�NAME��<global>
��@&��NAME��"/home/jai/Documents/ctf/bbctf/re.c���    �
�y)��FULL_NAME��+/home/jai/Documents/ctf/bbctf/re.c:<global>�NAME��<global>�
��  �   (�  k�  �
�
�
�
�   �
```
On running `strings` command on it, the output contained many strings like `LINE_NUMBER` `ORDER` `PARSER_TYPE_NAME` `CODE` and also contained some code segments
```c
grimline >> strings cpg.bin
....
....
....
LINE_NUMBER
ORDER
PARSER_TYPE_NAME
ForStatement
CODE
 for (u8 i = 1; i <= key[1]; i++)
ARGUMENT_INDEX
COLUMN_NUMBER
LINE_NUMBER
CODE
TYPE_FULL_NAME
....
....
....
```
the `for` loop code segment was interesting, the file seemed like something related to CPG(Code Property Graph) representation, But i didn't know anything about CPG, so i examined the `strings` output for more details, i further came accross many more code segments
```c
...
...
CODE
while (n > 0)
...
CODE
printf("%llu", out[i])
...
"%llu"
...
CODE
printf("\n")
...
...
```
we can also note that all the code segments are preceded by the string `CODE`, so i `grepped` the `strings` output
```rust
grimline >> strings cpg.bin| grep CODE -A1|head -n30
CODE
u64 n
--
CODE
COLUMN_NUMBER
--
CODE
ARGUMENT_INDEX
--
CODE
TYPE_FULL_NAME
--
CODE
r = 0
--
CODE
ARGUMENT_INDEX
--
CODE
ARGUMENT_INDEX
--
CODE
while (n > 0)
--
CODE
n > 0
--
CODE
ARGUMENT_INDEX
--
```
after cleaning up the strings, we get
```rust
u64 n
r = 0
while (n > 0)
n > 0
r |= n & 0xff
n & 0xff
0xff
r <<= 1
n >>= 1
r >>= 1
return r;
u8 *s
u32 *idx
*key = table[s[0]]
table[s[0]]
table
s[0]
...
...
...
key[1]
return val;
char *s
u32 n
sz = 0
idx = 0
while (idx < n)
idx < n
*key = table[s[idx]]
table[s[idx]]
table
s[idx]
idx += key[1] + 1
key[1] + 1
key[1]
sz++
return sz;
idx = 0
in[] = { 0, 3, 9, 1, 1, 4, 5, 2, 7, 6, 1, 5, 0, 6, 3, 9, 8, 4, 9, 9, 2,\n        1, 3, 7, 6, 5, 4, 6, 1, 1, 2, 3, 3, 2, 1, 0, 3, 8, 2, 7 }
...
...
...
```
and after cleaning all the repeated code we finally get a rough c code
```c
u64 n
r = 0
while (n > 0){
    r |= n & 0xff
    r <<= 1
    n >>= 1
}
r >>= 1
return r;

u8 *s
u32 *idx

*key = table[s[0]]
s[0] &= key[0]
val = 0
val |= s[0]

for (u8 i = 1; i <= key[1]; i++){
    val <<= 1
    val |= s[i]
    *idx += key[1] + 1
return val;

char *s
u32 n
sz = 0
idx = 0
while (idx < n){
    *key = table[s[idx]]
    idx += key[1] + 1
    sz++
return sz;

idx = 0
in[] = { 0, 3, 9, 1, 1, 4, 5, 2, 7, 6, 1, 5, 0, 6, 3, 9, 8, 4, 9, 9, 2, 1, 3, 7, 6, 5, 4, 6, 1, 1, 2, 3, 3, 2, 1, 0, 3, 8, 2, 7 }

len = sizeof(in) / sizeof(u8)
sz = calc_size(in, len)
idx_o = 0
*out = (u64*)malloc(sz * sizeof(u64))

while (idx < len){
    &out[idx_o++] = resolve(in + idx, &idx)

for (u32 i = 0; i < idx_o; i++)
    printf("%llu", out[i])
printf("\n")
return 0;
```
we can also see that an array named `table` is being referred here which appears to be same as the one from the provided `Hint`.

i then converted the above c code to python which involved removing some size calculation and memory allocation functions 
```python
table = [ [0xff, 1], [0xfe, 2], [0xfd, 3], [0xfc, 4], [0xfb, 5], [0x00, 5], [0x01, 4], [0x02, 3], [0x03, 2], [0x04, 1] ]

def resolve(s,idx):
    key = table[s[0]]
    s[0] &= key[0]
    val = 0
    val |= s[0]
    for i in range(1,key[1]+1):
        val <<= 1
        val |= s[i]
    idx += key[1] + 1
    return (idx,val)
def main():
    idx = 0
    ln = [ 0, 3, 9, 1, 1, 4, 5, 2, 7, 6, 1, 5, 0, 6, 3, 9, 8, 4, 9, 9, 2, 1, 3, 7, 6, 5, 4, 6, 1, 1, 2, 3, 3, 2, 1, 0, 3, 8, 2, 7 ]
    l = len(ln)
    idx_o = 0
    out= [0]*l
    while (idx < l):
        (idx,out[idx_o]) = resolve(ln[idx:], idx)
        idx_o+=1
    for i in range(0,idx_o): 
        print(out[i],end='')
    print()
    return 0
main()
```
after running the above python code we get some integer output `311329622193015237` and the flag is `flag{311329622193015237}`

Initially i thought that it would be hard to solve, mostly because of the low number of solves, but it came out pretty easy.

It was a really good challenge :)
