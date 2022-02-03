import socket
import threading
from time import time

class DNS_Relay_Server:      #一个relay server实例，通过缓存文件和外部地址来初始化
    def __init__(self,cache_file,name_server):
        #url_IP字典:通过域名查询ID
        self.url_ip = {}
        self.cache_file = cache_file
        self.load_file()
        self.name_server = name_server
        #trans字典：通过DNS响应的ID来获得原始的DNS数据包发送方
        self.trans = {}    

    def load_file(self):
        '''读取配置文件，识别ip和name并存入url_ip中'''
        f = open(self.cache_file,'r',encoding='utf-8')
        for line in f:
            ip,name = line.split(' ')   #split分割出ip和name
            self.url_ip[name.strip('\n')] = ip  #strip删除name中得换行符
        f.close()

    def run(self):
        '''运行DNS_Relay_Server'''
        buffer_size = 512
        #用 socket（）函数来创建套接字，语法格式如socket.socket([family[, type[, proto]]])
        #family: 套接字家族可以使 AF_UNIX 或者 AF_INET
        #type: 套接字类型可以根据是面向连接的还是非连接分为 SOCK_STREAM 或 SOCK_DGRAM
        #protocol: 一般不填默认为 0
        #TCP是SOCK_STREAM,UDP是SOCK_DGRAM
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        #绑定地址（host,port）到套接字， 在 AF_INET下，以元组（host,port）的形式表示地址。
        server_socket.bind(('0.0.0.0',53))
        server_socket.setblocking(False)    #设置非阻塞
        # while循环不断地接收请求
        while True:
            try:
                # 接收 UDP 数据，与 recv() 类似，但返回值是（data,address）。其中 data 是包含接收数据的字符串，#address 是发送数据的套接字地址
                data,addr = server_socket.recvfrom(buffer_size)
                #多线程编程，创建Thread对象来新建子线程，start()可以启用Thread对象
                #子线程运行self.handle()函数
                threading.Thread(target=self.handle,args=(server_socket,data,addr)).start()
            except Exception:
                pass

    def handle(self,server_socket,data,addr):
        '''处理收到的data和addr'''
        start_time = time()
        RecvDp = DNS_Package(data)
        id = RecvDp.get_id()
        #是请求报文
        if RecvDp.is_query():
            name = RecvDp.get_name()
            if name in self.url_ip and RecvDp.is_A():
                ip = self.url_ip[name]
                response = RecvDp.generate_response(ip)
                server_socket.sendto(response,addr)
                if ip == "0.0.0.0":
                    #Intercept
                    print('Intercept time=',(time()-start_time))
                else:
                    #local resolve
                    print('Resolve time=',(time()-start_time)) 
                
            else:
                #Relay
                server_socket.sendto(data,self.name_server)
                self.trans[id] = (addr,start_time)
            
        #是响应报文
        if RecvDp.is_response():
            if id in self.trans:
                target_addr,start_time = self.trans[id]
                server_socket.sendto(data,target_addr)
                print('Relay time=',(time()-start_time))
                del self.trans[id]

class query_MSG:
    def __init__(self,Msg_arr):
       self.data = Msg_arr

    def ID(self):
        return (self.data[0] << 8 ) + self.data[1]

    def QR(self):
        return self.data[2] >> 7 #消息是查询(0)还是响应(1)

    def opcode(self):
        return (self.data[2] >> 3) % 16 #这个消息中查询的种类。这个值由查询的发起者设置，它被复制进响应中。这个值的具体取值是0(标准查询(QUERY)) 1(反向查询(IQUERY)) 2(服务器状态请求(STATUS)) 3-15(保留将来使用)
        
    def AA(self):
        return (self.data[2] >> 2) % 2 #这个位在响应中有效，这个位规定进行回应的名称服务器是问题部分中域名的权威(名称服务器)。注意，由于别名，回答部分的内容可以有多个所有者名称。AA位对应匹配查询名称的名称，或者对应回答部分中第一个所有者名称。
        
    def TC(self):
        return (self.data[2] >> 1) % 2 #表示这条消息由于长度大于传送通道上准许的长度而被截断。
        
    def RD(self):
        return self.data[2] % 2 #在查询中这个位可以置 1，并且被复制进响应中。如果 RD 置 1，它引导名称服务器递归跟踪查询。
        
    def RA(self):
        return self.data[3] >> 7 #在响应中这个字段被置 1 或被清零，指示在名称服务器中是否支持递归查询。
        
    def Z(self):
        return (self.data[3] >> 4) % 8 #保留将来使用。在所有查询和响应中此位必须置 0。

    def RCODE(self):
        return self.data[3] % 16 #0 没有出错条件1 格式错误---名称服务器不能解释查询。2 服务器故障---由于与名称服务器有关的问题，名称服务器不能处理这个查询。3 名称错误---仅对来自权威名称服务器的响应有意义，这个代码预示在该查询中被查询的域名不存在。4 未实现---名称服务器不支持请求的查询种类。5 拒绝---由于策略原因名称服务器拒绝执行指定的操作。例如，名称服务器可能不希望提供信息给特定的请求者，或者名称服务器可能不希望为特定的数据执行特定的操作(例如，区域传递)。6-15 保留将来使用。

    def QDCOUNT(self):
        # Questions
        return (self.data[4] << 8) + self.data[5] #无正负号 16 位整数，它规定问题部分中条目的数量。

    def ANCOUNT(self):
        # Answer RRs
        return (self.data[6] << 8) + self.data[7] #无正负号 16 位整数，它规定回答部分中资源记录的数量。
        
    def NSCOUNT(self):
        # Authority RRs
        return (self.data[8] << 8) + self.data[9] #无正负号 16 位整数，它规定权威记录部分中名称服务器资源记录的数量。

    def ARCOUNT(self):
        # Additional RRs
        return (self.data[10] << 8) + self.data[11] #无正负号 16 位整数，它规定附加记录部分中资源记录的数量。

    def query(self):
        '''返回QNAME,QTYPE,QCLASS,name_length'''
        i = 12
        # name是QNAME
        dot_flag = 0
        name = ""
        while True:
            length = self.data[i]
            i = i + 1
            if length == 0:
                break
            if dot_flag:
                name += "."
            dot_flag = 1
            for j in range(i,i + length):
                name += chr(self.data[j])
            i = i + length

        #name_length
        name_length = i - 12

        # qtype
        qtype = (self.data[i] << 8) + self.data[i+1]
        i = i + 2
        # qclass
        qclass = (self.data[i] << 8) + self.data[i+1]

        return name,qtype,qclass,name_length

class DNS_Package:        #一个DNS Frame实例，用于解析和生成DNS帧
    def __init__(self,data):
        #bytearray将字符串转化为字节序列
        #Msg_arr = bytearray(data)
        self.data = data
        msg = query_MSG(self.data)
        #ID
        self.ID = msg.ID()
        # FLAGS
        self.QR = msg.QR()
        self.opcode = msg.opcode()
        self.AA = msg.AA()
        self.TC = msg.TC()
        self.RD = msg.RD()
        self.RA = msg.RA()
        self.Z = msg.Z()
        self.RCODE = msg.RCODE()
        self.QDCOUNT = msg.QDCOUNT()
        self.ANCOUNT = msg.ANCOUNT()
        self.NSCOUNT = msg.NSCOUNT()
        self.ARCOUNT = msg.ARCOUNT()
        self.QNAME,self.QTYPE,self.QCLASS,self.name_length = msg.query()
    
    def is_query(self):
        return self.QR == 0

    def is_response(self):
        return self.QR == 1

    def generate_response(self,ip):
        self.flags = 0x8180 if ip != '0.0.0.0' else 0x8583
        #Intercepted是拦截
        #if not Intercepted:
        res = bytearray(32 + self.name_length)#返回一个特定长度的初始化数组
        # header段
        #ID
        res[0] = self.ID >> 8
        res[1] = self.ID % 256
        #FLAGS
        res[2] = self.flags >> 8
        res[3] = self.flags % 256
        #QDCOUNT
        res[4] = self.QDCOUNT >> 8
        res[5] = self.QDCOUNT % 256
        #ANCOUNT
        res[6] = 0
        res[7] = 1
        #NSCOUNT
        res[8] = self.NSCOUNT >> 8
        res[9] = self.NSCOUNT % 256
        #ARCOUNT
        res[10] = self.ARCOUNT >> 8
        res[11] = self.ARCOUNT % 256
        # query段
        for i in range(12, 16 + self.name_length):
            res[i] = self.data[i]
        # answer段
        #NAME是资源记录包含的域名,是两个字节
        self.ANAME = self.QNAME
        #RDATA数据的含义,TYPE=A的值为1
        self.TYPE = 1
        #RDATA的类型
        self.CLASS = 1
        #资源记录可以缓存的时间
        self.TTL = 200
        #RDATA的长度
        self.rdlength = 4
        #不定长字符串来表示记录
        s = ip.split(".")
        self.rdata=[]
        for i in range(0,4):
            self.rdata.append(bytes(s[i],encoding="utf-8"))
        res_i = 16 + self.name_length
        #NAME
        self.answer_name = 0xc00c
        res[res_i] = self.answer_name >> 8 
        res[res_i + 1] = self.answer_name % 256
        res_i = res_i + 2
        #TYPE
        res[res_i] = self.TYPE >> 8
        res_i = res_i + 1
        res[res_i] = self.TYPE % 256
        res_i = res_i + 1
        #CLASS
        res[res_i] = self.CLASS >> 8
        res_i = res_i + 1
        res[res_i] = self.CLASS % 256
        res_i = res_i + 1
        #TTL
        res[res_i] = self.TTL >> 24
        res_i = res_i + 1
        res[res_i] = (self.TTL >> 16) % 256
        res_i = res_i + 1
        res[res_i] = (self.TTL >> 8) % 256
        res_i = res_i + 1
        res[res_i] = self.TTL % 256
        res_i = res_i + 1
        #RDLENGTH
        res[res_i] = self.rdlength >> 8
        res_i = res_i + 1
        res[res_i] = self.rdlength % 256
        res_i = res_i + 1
        #RDATA
        for i in range(0,4):
            res[res_i + i] = int(self.rdata[i])
        return bytes(res)
        
    def get_name(self):
        return self.QNAME

    def get_id(self):
        return self.ID

    def is_A(self):
        return self.QTYPE == 1

if __name__ == '__main__':
    cache_file = 'example.txt'
    name_server=('223.5.5.5',53)    #阿里DNS
    relay_server = DNS_Relay_Server(cache_file,name_server)   #构造一个DNS_Relay_Server实例
    relay_server.run()