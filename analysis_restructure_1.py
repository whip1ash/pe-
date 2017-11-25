#coding=utf-8
#第一次重构代码 把原来面向过程给改为面向对象
#准备接受参数实现各种功能
import sys

class AutoVivification(dict):
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self,item)
        except KeyError:
            value = self[item] = type(self)()
            return value

class Analysis_header(object):
    # def __init__(self):
    #     self.__analysi_resutl = 'test'
    # analysis_res = AutoVivification()
    analysis_res = {}
    file_offset = 0x0

    def analysis_all(self):
        self.analysis_IMAGE_DOS_HEADER()
        self.analysis_IMAGE_NT_HEADER()

    #return (string)content (int)next_offset next_offset和content是一个值 类型不同而已 方便使用
    def __file_pointer(self, offset, length):
        file_handle.seek(offset,0)
        #转换大端序 用交换法好像更复杂了 我还是决定用我以前的方法 先切片分列表 再从列表转换回来
        data = file_handle.read(length).encode('hex')

        buf_list = list(data)
        i=2
        #把字符串转换成列表 [01 23 45 67 89 AB CD EF] EFCDAB8967452310
        while i<=len(buf_list):
            buf_list.insert(i,' ')
            #插入空格后的列表
            break_list = ''.join(buf_list)
            i+=3
        #01 23 45 67 89 AB CD EF
        break_list = break_list.split(' ')
        #去最后一个空元素
        break_list = break_list[:-1]
        raw_data = ''.join(break_list)
        #倒序
        break_list = break_list[::-1]
        #恢复成字符串
        content = ''.join(break_list)
        #现在的data是字符串 方便显示但是不方便使用 所以我们把它转成十六进制的数据 方便下面的调用
        next_offset = int(content,base=16)

        return {'content':content,'next_offset':next_offset,'raw_data':raw_data,'offset':hex(self.file_offset),'length':length}

    #总要一遍遍去做 太麻烦 把这个过程封装起来
    #最多四层吧
    def __analysis(self,file_offset,len,Section_name,Sub_Section_name,Ss_Section_name='',Sss_Section_name=''):
        return_data = self.__file_pointer(file_offset,len)

        #这里非常坑 用直接赋值的方法会重置掉一些值 所以我们在这里有setdefualt(key,value)
        #下次重构的时候这里用try{}catch(){}
        if  Ss_Section_name.strip() =='' and Sss_Section_name.strip() =='':
            if not self.analysis_res.has_key(Section_name):
                self.analysis_res[Section_name] = {Sub_Section_name:return_data}
            else:
                self.analysis_res['test1'] = {'test2':'test3'}
                self.analysis_res['test1'] = {'test3':'test4'}
                self.analysis_res[Section_name].setdefault(Sub_Section_name,return_data)

        elif Sss_Section_name.strip() == '':
            #这里需要有一个判断 要不会重置字典 因为我要添加一个二级目录
            #先判断第一个key是不是存在 如果不存在的话
            #这里就是坑了 还只能这样去用setdefault
            if not self.analysis_res.has_key(Section_name):
                self.analysis_res[Section_name] = {Sub_Section_name:{Ss_Section_name:return_data}}
            elif not self.analysis_res[Section_name].has_key(Sub_Section_name):
                self.analysis_res[Section_name][Sub_Section_name] = {Ss_Section_name:return_data}
            else:
                self.analysis_res[Section_name][Sub_Section_name].setdefault(Ss_Section_name,return_data)

        else :
            if not self.analysis_res.has_key(Section_name):
                self.analysis_res[Section_name] = {Sub_Section_name:{Ss_Section_name:{Sss_Section_name:return_data}}}
            elif not self.analysis_res[Section_name].has_key(Sub_Section_name):
                self.analysis_res[Section_name][Sub_Section_name] = {Ss_Section_name:{Sss_Section_name:return_data}}
            elif not self.analysis_res[Section_name][Sub_Section_name].has_key(Ss_Section_name):
                self.analysis_res[Section_name][Sub_Section_name][Ss_Section_name] = {Sss_Section_name:return_data}
            else:
                self.analysis_res[Section_name][Sub_Section_name][Ss_Section_name].setdefault(Sss_Section_name,return_data)

        if Ss_Section_name.strip() == '' and Sss_Section_name  ==  '' :
            self.analysis_res[Section_name][Sub_Section_name] = return_data

        elif Sss_Section_name.strip() == '':
            self.analysis_res[Section_name][Sub_Section_name][Ss_Section_name] = return_data
        else :
            self.analysis_res[Section_name][Sub_Section_name][Ss_Section_name][Sss_Section_name] = return_data

        self.file_offset += len

    def analysis_IMAGE_DOS_HEADER(self):
        self.file_offset = 0x3c
        self.__analysis(self.file_offset, 2, 'IMAGE_DOS_HEADER', 'E_lfanew')

    def analysis_IMAGE_NT_HEADER(self):
        #这一段的基地址
        self.file_offset = self.analysis_res['IMAGE_DOS_HEADER']['E_lfanew']['next_offset']
        Signature = 0x0
        Signature_len = 0x4
        offset = self.file_offset + Signature
        Signature = self.__file_pointer(offset,T2L('DWORD'))
        self.analysis_res['IMAGE_NT_HEADERS'] = {'Signature':Signature}
        self.file_offset += Signature_len

        #从这往后的分析都调用了封装方法
        #Image_File_Header 这中间我们就侧重 Machine NumberOfSections SizeOfOptionalHeader Charactenistics
        #Machine
        self.__analysis(self.file_offset,2,'IMAGE_NT_HEADERS','Image_File_Header','Machine')
        #NumberOfSections
        self.__analysis(self.file_offset,2,'IMAGE_NT_HEADERS','Image_File_Header','NumberOfSections')
        self.file_offset += 12
        #SizeOfOptionHeader 可选头大小
        self.__analysis(self.file_offset,2,'IMAGE_NT_HEADERS','Image_File_Header','SizeOfOptionHeader')
        #Characteristics    文件信息标志(exe/dll...)
        self.__analysis(self.file_offset,2,'IMAGE_NT_HEADERS','Image_File_Header','Characteristics')
        self.__analysis(self.file_offset,2,'IMAGE_NT_HEADERS','Image_Optional_Header','Magic')
        self.file_offset += 14
        #AddressOfEntryPoint 程序入口个RVA地址
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','AddressOfEntryPoint')
        #BaseOfCode 代码其实RVA
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','BaseOfCode')
        #BaseOfData 数据块起始RVA
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','BaseOfData')
        #ImageBase 基址
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','ImageBase')
        #SectionAlignment 块对齐
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','SectionAlignment')
        #FileAligment 文件对齐
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','FileAlignment')
        self.file_offset +=16
        #SizeOfImage 映像大小
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','SizeOfImage')
        #SizeOfHeader 块钱头部大小
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','SizeOfHeader')
        self.file_offset+=28
        self.__analysis(self.file_offset,4,'IMAGE_NT_HEADERS','Image_Optional_Header','NumberOfRvaAndSizes')


        self.__analysis(self.file_offset,8,'IMAGE_NT_HEADERS','Image_Optional_Header','Image_Data_Directorys','Image_directory_entry_export')
        self.__analysis(self.file_offset,8,'IMAGE_NT_HEADERS','Image_Optional_Header','Image_Data_Directorys','Image_directory_entry_import')






    def display(self,dictionary,loop_flag=0):
        #一层层检测去格式化
        # for x in range(len(dictionary)):
        #     dict_key_1 = dictionary.keys()[x]
        #     if isinstance(dictionary[dict_key_1],dict):
        #         #第二层
        #         temp_dict_2 = dictionary[dict_key_1]
        #         for n in range(len(temp_dict_2)) :
        #             dict_key_2 = temp_dict_2.keys()[n]
        #             if isinstance(temp_dict_2[dict_key_2],dict):
        #                 #第三层
        #                 temp_dict_3 = temp_dict_2[dict_key_2]
        #                 print temp_dict_3
        #                 break
        #             print dict_key_2
        #
        #     print dictionary[dict_key_1]

        # for x in range(len(dictionary)):
        #     dict_key_1 = dictionary.keys()[x]
        #     print('{0}{1}{0}'.format('-' * 20, dict_key_1))
        #     if isinstance(dictionary[dict_key_1],dict):
        #         #第二层
        #         temp_dict_2 = dictionary[dict_key_1]
        #         for n in range(len(temp_dict_2)):
        #             dict_key_2 = temp_dict_2.keys()[n]
        #             print dict_key_2
        #             if isinstance(temp_dict_2[dict_key_2],dict):
        #                 #第三层
        #                 temp_dict_3 = temp_dict_2[dict_key_2]
        #                 if not temp_dict_3.keys() == ['content', 'raw_data', 'length', 'next_offset',
        #                                                           'offset']:
        #                     for m in range(len(temp_dict_3)):
        #                         dict_key_3 = temp_dict_3.keys()[m]
        #                         print  ' '*5,dict_key_3#,' '*5,temp_dict_3[dict_key_3]
        #
        #                         if isinstance(temp_dict_3[dict_key_3],dict):
        #                             #第四层 重写的时候用一个函数式调用 有点复杂了 嵌套层数有点深了
        #                             temp_dict_4 = temp_dict_3[dict_key_3]
        #                             if not temp_dict_4.keys() == ['content', 'raw_data', 'length', 'next_offset', 'offset']:
        #                                 for y in range(len(temp_dict_4)):
        #                                     dict_key_4 = temp_dict_4.keys()[y]
        #                                     print ' '* 10,dict_key_4#," "* 5 ,temp_dict_4[dict_key_4]

        #尝试重写成一个循环方法

        for x in range(len(dictionary)):
            dict_key = dictionary.keys()[x]
            if  loop_flag == 0 :
                print('{0}{1}{0}'.format('-' * 20, dict_key))
            else:
                try:
                    # print  ' '*5*(loop_flag-1),dict_key,\
                    #     '[',dictionary[dict_key]['offset'],']',\
                    #     '(',dictionary[dict_key]['length'],')',\
                        # ' '*5,dictionary[dict_key]['raw_data'],\
                        # ''*5,dictionary[dict_key]['content']

                    print ' '*5*(loop_flag-1),'%-30soffset: %-8slength: %-1s raw_data: %-17scontent: %-20s'%(dict_key,dictionary[dict_key]['offset'],dictionary[dict_key]['length'],dictionary[dict_key]['raw_data'],dictionary[dict_key]['content'])
                except KeyError:
                    print dict_key
                    # print ''

            if isinstance(dictionary[dict_key],dict):
                temp_dict = dictionary[dict_key]
                if not temp_dict.keys() == ['content', 'raw_data', 'length', 'next_offset',
                                                  'offset']:
                    # print temp_dict.keys()
                    self.display(temp_dict,loop_flag+1)
                # else:
                #     print  ' '*5*(loop_flag-1),dict_key,' '*5,temp_dict['offset'],' '*5,temp_dict['length'],' '*5,temp_dict['raw_data']




    def test(self):
       pass

#type to length
def T2L(Type):
    if Type=='byte':
        return 1
    if Type=='WORD':
        return 2
    if Type=='DWORD':
        return 4

if __name__ == '__main__':
    file_dir = sys.argv[1]
    file_handle = open(file_dir,'rb')
    analysis_header = Analysis_header()
    analysis_header.analysis_all()
    analysis_header.display(analysis_header.analysis_res)
    # print analysis_header
    #测试AutoVivification
    # dictionary = AutoVivification()
    # dictionary['test0']['test1']= '233333333'
    # dictionary['test0']['test1']['test2'] = 'test '
    # print dictionary

    #print list(analysis_header.analysis_res)
