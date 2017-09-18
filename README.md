<<<<<<< HEAD
遗留问题：<br>
1 topology.c中生成96位签名时，传进去的ts是何时获取的。     (已经解决)<br>
2 What's the difference between fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) and fcntl(udp_sockd,F_SETFL,O_NONBLOCK)<br>
3 recvfrom收到的数据，数据结构需要优化成Buffer<br>
4 数据包中latency（迟延）没有处理<br>5 代码流程中未处理Moon，现在默认没有moons<br>
6 报文的分片处理没有实现，现在默认不分片<br>
7 互斥锁没有实现<br>
8.networks的概念，啥时候生成的networks<br>
9._doNETWORK_CONFIG_REQUEST中request函数用到了线程池，需要研究一下<br>
10.planet在join流程中的作用？感觉没啥作用<br>
11.bool _doMULTICAST_LIKE(Peer *peer,Path *path,Buffer *buf)未移植。<br>
12.core-dev\node\InetAddress.cpp netmaskbits函数实现貌似有问题，逻辑不对。待验证(已验证)<br>
13.写member json文件时没有换行<br>
14."tags": [ ]中有空格，可能需要去掉(已解决)<br>
15.一些request报文没有走到tryDecode流程，原因需要进一步确认<br>
16.controller写json文件时， "ipAssignments"写了多个IP地址(已解决)<br>
17.member的json文件为空时，controller二次启动出现段错误<br>
18.peer地址分配好后，peers之间无法ping通<br>
19.报文发送前的compress还没做，等到全部功能完成后再添加<br>
20.PacketId 校验流程预留<br>


ZeroTierOne进度：
1、理清了peer加入member后如何同其他peers通信的流程
2、Peers分配到IP地址后已经能正常up新的网卡

To-DO List:
1、处理VERB_NETWORK_CREDENTIALS报文：addCredential函数需要移植，_gatherAuth数据结构需要重新设计 (工作量较小)
功能：将报文解序列化得到com,cap,tag,coo,revocation，对应做addCredential操作。

2、处理VERB_MULTICAST_LIKE报文：要移植Multicaster类，设计数据结构_groups、MulticastGroupMember、group status: key和group status的对应关系(工作量较大)
功能：收到VERB_MULTICAST_LIKE后，将member加入的Multicaster groups中。

3、处理VERB_MULTICAST_GATHER报文：gather函数要实现(工作量较小)
功能：将multicast groups中的members(只包含ZT addr)发给peer

4、处理VERB_WHOIS报文：requestWhois函数需要实现(工作量较小)
功能：返回被查询的peer的Identity

5、onRemotePacket函数中需要增加新的逻辑，主要函数包括sendDirect、getRendezvousAddresses、_shouldUnite、getUpstreamPeer(工作量还行)
功能：发送VERB_RENDEZVOUS报文（返回members的实际IP地址和端口号），转发peer的push_direct_path的报文，hop+1

6、处理Echo报文：新增_doECHO函数(工作量较小)
功能：返回一个内容一样的报文



=======
To Do List<br>
1.mutex_lock <br>
2.multicast threads<br>
3.tasks lists<br>
4.unknown

>>>>>>> 438178aa6a6dcadfe7f4e22fa55a4f52cb69d137
