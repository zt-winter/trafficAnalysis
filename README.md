# 说明

### TCP重组

[开源项目中相关代码](github.com/asmcos/sniffer/blob/master/sniffer.go#L1056)

* gopacket中关于TCP重组有两个库，一个是tcpassembly，另一个是reassembly。tcpassembly功能不完善，bug比较多，并且已经很久没有维护。reassembly非常完善，因此在TCP重组实现时选择使用reassembly

* 一般实现TCP重组过程中基本变量初始化为steamFacotry -> streamPool -> assembler -> AssembleWithContext -> FlushWithOptions

* AssembleWithContext在函数执行过程调用三个重要的函数StreamFactory.New(Creating a stream)	ReassembledSG(on a single stream)	ReassemblyComplete(on the same stream)

* 其中StreamFactory.New函数，由接口StreamFactory定义,AssembleWithContext函数调用getConnection函数，getConnection函数会调用StreamFactory.New()。StreamFactory接口定义New方法，需要使用者自己去构造New函数，新建的stream就可以在New函数中进行操作。[getConnection函数位置](https://github.com/google/gopacket/blob/v1.1.19/reassembly/memory.go#L233)

* ReassembledSG函数，在接口Stream中定义，AssembleWithContext函数调用sendToConnection函数，再调用ReassembledSG。同样需要使用者自己去构造ReassembledSG函数。[sendToConnection函数位置](https://github.com/google/gopacket/blob/v1.1.19/reassembly/tcpassembly.go#L1101)

* ReassemblyComplete函数，在接口Stream中定义，AssembleWithContext函数调用sendToConnection函数，再调用closeHalfConnection函数，再调用ReassemblyComplete函数。[closeHalfConnection函数位置](https://github.com/google/gopacket/blob/v1.1.19/reassembly/tcpassembly.go#L1198)

* 在接口stream中还定义了Accept函数，由该函数可以实现如何选择正确的TCP数据包加入到流中

__目前的实验不需要对流量做完整的tcp重组，还是用五元组对流量分类__

