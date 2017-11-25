# coding=utf-8

#二进制读文件脚本
import sys

file = sys.argv[1]

f = open(file,"rb")
f.seek(0,0)
while 1:
    byte = f.read(16)
    hex_byte = byte.encode('hex')
    hex_byte= list(hex_byte)
    hex_byte_len = len(hex_byte)
    i = 2

    #python 在insert之前就算出来你要insert后的list长度 index根据新长度来定
    while i <= hex_byte_len+hex_byte_len/2:
        hex_byte.insert(i,' ')
        hex_byte1 = ''.join(hex_byte)
        i+=3

    if hex_byte != []:
        print hex_byte1

    else:
        break
f.close()