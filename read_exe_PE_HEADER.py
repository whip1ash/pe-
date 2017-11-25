# coding=utf-8
#二进制读文件脚本
import sys

file_dir = sys.argv[1]
f = open(file_dir,"rb")

#封装一个读取文件的函数 文件句柄 初始偏移(相对文件的偏移) 读取文件的长度 相对初始偏移的偏移 正常序的值输出 格式化的值输出
def file_pointer_read(file_handle,position,length,offset = 0,normal = 0,raw = 0):
    if  length == '':
        file_handle.seek(0,2)
        length = file_handle.tell()

    file_handle.seek(position,offset)
    raw_content = file_handle.read(length)
    hex_content = raw_content.encode('hex')
    return hex_format(hex_content,normal,raw)

#我知道我这里用了一个很蠢的方法
#raw_byte_content 文件里的数据 不带空格
#format_byte_content 文件里的数据 带空格
#format_byte_normal 正常序的数据
def hex_format(string,normal=0,raw_byte_print=0):
    return_data = {'raw_byte_content':string}
    hex_byte = list(string)
    hex_byte_len = len(hex_byte)
    i = 2
    #python 在insert之前就算出来你要insert后的list长度 index根据新长度来定
    while i<=hex_byte_len+hex_byte_len/2:
        hex_byte.insert(i,' ')
        hex_string = ''.join(hex_byte)
        i+=3

    return_data['format_byte_content'] = hex_string
    #输出本来在文件中的值(小端序)
    if raw_byte_print == 1:
        print hex_string



    byte_list = hex_string.split(' ')
    byte_list = byte_list[:-1]
    byte_list = byte_list[::-1]
    hex_string = ''.join(byte_list)

    # 正常序
    return_data['format_byte_normal'] = hex_string
    if  (normal == 1):
        print hex_string


    return return_data

def lengthToType(length):
    if length == 1:
        return 'byte'
    if length == 2:
        return 'WORD'
    if length == 4:
        return 'DWORD'

#我讨厌python的缩进
#现在我们从头开始来扣一下PE结构 应该是很简单的工作
#IMAGE_DOS_HEADER的0x3c处有一个E_lfanew DWORD 指向 IMAGE_NT_HEADER

E_lfanew = 0x3c
E_lfanew_content = file_pointer_read(f,E_lfanew,4,0)
IMAGE_NT_HEADER = E_lfanew_value = int(E_lfanew_content['format_byte_normal'],16)
IMAGE_NT_HEADER_size = 0xf8
#所以整个PE头的size是IMAGE_NT_HEADER+0xf8(The length of IMAGE_NT_HEADER)
#让我们先把整个PE头扣下来
PE_size = IMAGE_NT_HEADER + IMAGE_NT_HEADER_size
#一下子全输出太难看了 我们来格式化一下
print '===================PE_HEADER==================='
format_offset = 0
remainder = PE_size % 16
while format_offset < PE_size:

    if PE_size-format_offset < 16:
        file_pointer_read(f, format_offset, remainder, 0, 0, 1)
        break
    else:
        file_pointer_read(f, format_offset, 16, 0, 0, 1)
        format_offset += 16
print '===================PE_HEADER==================='

print '\nIMAGE_DOS_HEADER=>'
print '     [%x] E_lfanew (%s) -> %s' % (E_lfanew,lengthToType(4),E_lfanew_content['format_byte_content'])
print '                     value -> %s' % (E_lfanew_value)
# IMAGE_NT_HEADER_pos = int(file_pointer_read(f,E_lfanew,4),16)

# PE_size = IMAGE_NT_HEADER_pos + 0xf8
# print file_pointer_read(f,0,PE_size,0,1)
f.close()

