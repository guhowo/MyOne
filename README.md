遗留问题：<br>
1 topology.c中生成96位签名时，传进去的ts是何时获取的。     (已经解决)<br>
2 What's the difference between fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) and fcntl(udp_sockd,F_SETFL,O_NONBLOCK)<br>
3 recvfrom收到的数据，数据结构需要优化成Buffer (已经解决)<br>
4 数据包中latency（迟延）没有处理<br>5 代码流程中未处理Moon，现在默认没有moons (不需要)<br>
6 报文的分片处理没有实现，现在默认不分片(不需要)<br>
7 互斥锁没有实现<br>
8.networks的概念，啥时候生成的networks<br>
9._doNETWORK_CONFIG_REQUEST中request函数用到了线程池，需要研究一下<br>
10.planet在join流程中的作用？感觉没啥作用<br>
11.bool _doMULTICAST_LIKE(Peer *peer,Path *path,Buffer *buf)未移植。<br>
12.core-dev\node\InetAddress.cpp netmaskbits函数实现貌似有问题，逻辑不对。(已经解决)<br>
13.写member json文件时没有换行（不影响功能）<br>
14."tags": [ ]中有空格，可能需要去掉(已经解决)<br>
15.一些request报文没有走到tryDecode流程，原因需要进一步确认 (已经解决，走了转发流程)<br>
16.controller写json文件时， "ipAssignments"写了多个IP地址(已经解决)<br>
17.member的json文件为空时，controller二次启动出现段错误 (已经解决)<br>
18.peer地址分配好后，peers之间无法ping通(已经解决)<br>
19.报文发送前的compress还没做，等到全部功能完成后再添加(已经解决)<br>
20.PacketId 校验流程预留(已经解决)<br>
21.没有增加bestPath概念，需要研究一下<br>



ZeroTierOne进度：<br>
	完成MULTICAST_GATHER、MULTICAST_LIKE、NETWORK_CREDENTIALS报文相关功能，至此network中的peer可以直接通信，ping通对方<br>

未解决问题：<br>
	对于大量请求需要多线程处理.目前是单线程，一个network支持256个member，<br>
	为了方便调试抓包，关闭了加密压缩流程，目前需要增加和线上的peer通信<br>
	优化代码，减少内存泄漏等隐含问题<br>

下一步计划：<br>
	优化代码，减少内存泄漏等隐含问题，增加加密压缩流程<br>





