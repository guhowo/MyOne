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


Credential类需要实现(deserialize)
CertficateofOwnership类需要移植(deserialize)
CertificateofMembership类需要移植(deserialize)
Revocation类需要实现(deserialize)
capability类需要移植(deserialize)
tag类需要实现(deserialize)
以上几个类都在独立文件中：
以上实现之后，可以得到Networconfig这个结构体

bool _doMULTICAST_LIKE(Peer *peer,Path *path,Buffer *buf)未移植。
core-dev\node\InetAddress.cpp netmaskbits函数实现貌似有问题，逻辑不对。待验证

写member json文件时没有换行
"tags": [ ]中有空格，可能需要去掉


ZeroTierOne发布：
1、Planet和Network的四次交互Hello，并正确保存path信息；
2、完成了Network的相应request报文的功能；
3、完成了Network生成、保存配置信息的功能；
4、完成了Network对peer的权限认证、证书认证的功能；
5、完成了Network发送config信息给请求者的功能；

下载地址：git@git.tisp.com:yangdan/zerotier_deamon.git
下一步计划：调试现有的功能，并完成Network响应组播报文doMulticast的功能