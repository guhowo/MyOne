#include "InetAddress.h"

unsigned int InetAddress_netmaskBits(const InetAddress *addr)        //port
{
    switch(addr->address.ss_family) {
        case AF_INET: return ntohs((uint16_t)(((const struct sockaddr_in *)addr)->sin_port));
        case AF_INET6: return ntohs((uint16_t)(((const struct sockaddr_in6 *)addr)->sin6_port));
        default: return 0;
    }
}

InetAddress _netmask(const InetAddress *self,const InetAddress *addr)
{
    InetAddress r;
    memcpy(&r,self,sizeof(r));
    switch(r.address.ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)&r)->sin_addr.s_addr = htonl((uint32_t)(0xffffffff << (32 - InetAddress_netmaskBits(addr))));
            break;
        case AF_INET6: {
            uint64_t nm[2];
            const unsigned int bits = InetAddress_netmaskBits(addr);
            if(bits) {
                nm[0] = Utils_hton_u64((uint64_t)((bits >= 64) ? 0xffffffffffffffffULL : (0xffffffffffffffffULL << (64 - bits))));
                nm[1] = Utils_hton_u64((uint64_t)((bits <= 64) ? 0ULL : (0xffffffffffffffffULL << (128 - bits))));
            }
            else {
                nm[0] = 0;
                nm[1] = 0;
            }
            memcpy(&(((struct sockaddr_in6 *)&r)->sin6_addr.s6_addr),nm,16);
        }    break;
    }
    return r;
}

bool InetAddress_containsAddress(const InetAddress *self,const InetAddress *addr)
{
    if (addr->address.ss_family == self->address.ss_family) {
        switch(self->address.ss_family) {
            case AF_INET: {
                const unsigned int bits = InetAddress_netmaskBits(self);
                if (bits == 0)
                    return true;
                return ((ntohl((uint32_t)(((const struct sockaddr_in *)addr)->sin_addr.s_addr)) >> (32 - bits)) == (ntohl((uint32_t)(((const struct sockaddr_in *)self)->sin_addr.s_addr)) >> (32 - bits)));
            }
            case AF_INET6: {
                InetAddress mask;
                _netmask(&mask,addr);
                const uint8_t *m = (const uint8_t *)&(((const struct sockaddr_in6 *)&mask)->sin6_addr.s6_addr);
                const uint8_t *a = (const uint8_t *)&(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr);
                const uint8_t *b = (const uint8_t *)&(((const struct sockaddr_in6 *)self)->sin6_addr.s6_addr);
                unsigned int i;
                for(i=0;i<16;++i) {
                    if ((a[i] & m[i]) != b[i])
                        return false;
                }
                return true;
            }
        }
    }
    return false;
}

void InetAddress_setPort(unsigned int port, InetAddress *addr)
{
    switch(addr->address.ss_family) {
        case AF_INET:
            ((struct sockaddr_in *)addr)->sin_port = htons((uint16_t)port);
            break;
        case AF_INET6:    
            ((struct sockaddr_in6 *)addr)->sin6_port = htons((uint16_t)port);
            break;
    }
}

const void *InetAddress_rawIpData(InetAddress *addr)
{
    switch(addr->address.ss_family) {
        case AF_INET: return (const void *)&(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
        case AF_INET6: return (const void *)&(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr);
        default: return 0;
    }
}

bool InetAddress_compare(const InetAddress *a, const InetAddress *b)
{
    if (a->address.ss_family == b->address.ss_family) {
        switch(a->address.ss_family) {
            case AF_INET:
                return (
                    (((const struct sockaddr_in *)a)->sin_port == ((const struct sockaddr_in *)b)->sin_port)&&
                    (((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr));
                break;
            case AF_INET6:
                return (
                    (((const struct sockaddr_in6 *)a)->sin6_port == ((const struct sockaddr_in6 *)b)->sin6_port)&&
                    (((const struct sockaddr_in6 *)a)->sin6_flowinfo == ((const struct sockaddr_in6 *)b)->sin6_flowinfo)&&
                    (memcmp(&(((const struct sockaddr_in6 *)a)->sin6_addr.s6_addr),&(((const struct sockaddr_in6 *)b)->sin6_addr.s6_addr),16) == 0)&&
                    (((const struct sockaddr_in6 *)a)->sin6_scope_id == ((const struct sockaddr_in6 *)b)->sin6_scope_id));
                break;
            default:
                return (memcmp(a,b,sizeof(InetAddress)) == 0);
        }
    }
    return false;

}


void InetAddress_Serialize(const InetAddress *InetAddr, Buffer *buf)
{
    // This is used in the protocol and must be the same as describe in places
    // like VERB_HELLO in Packet.hpp.
    switch(InetAddr->address.ss_family) {
        case AF_INET:
            append(buf, (uint8_t)0x04);
            append_databylen(buf, &(((struct sockaddr_in *)(&InetAddr->address))->sin_addr.s_addr), 4);
            append_uint16(buf, (uint16_t)InetAddress_netmaskBits(InetAddr)); // just in case sin_port != uint16_t
            return;
        case AF_INET6:
            append(buf, (uint8_t)0x06);
            append_databylen(buf, &(((struct sockaddr_in6 *)(&InetAddr->address))->sin6_addr.s6_addr), 16);
            append_uint16(buf, (uint16_t)InetAddress_netmaskBits(InetAddr)); // just in case sin_port != uint16_t
            return;
        default:
            append(buf, (uint8_t)0);
            return;
    }
}

bool InetAddress_ipsEqual(const InetAddress *a, const InetAddress *b)
{
    if (a->address.ss_family == b->address.ss_family) {
        if (a->address.ss_family == AF_INET)
            return (((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr);
        if (a->address.ss_family == AF_INET6)
            return (memcmp(((const struct sockaddr_in6 *)a)->sin6_addr.s6_addr, ((const struct sockaddr_in6 *)b)->sin6_addr.s6_addr,16) == 0);
        return (memcmp(a, b,sizeof(InetAddress)) == 0);
    }
    return false;
}


enum IpScope InetAddress_ipScope(const InetAddress *ipAddr)
{
    switch(ipAddr->address.ss_family) {

        case AF_INET: {
            const uint32_t ip = ntohl(((const struct sockaddr_in *)ipAddr)->sin_addr.s_addr);
            switch(ip >> 24) {
                case 0x00: return IP_SCOPE_NONE;                                      // 0.0.0.0/8 (reserved, never used)
                case 0x06: return IP_SCOPE_PSEUDOPRIVATE;                             // 6.0.0.0/8 (US Army)
                case 0x0a: return IP_SCOPE_PRIVATE;                                   // 10.0.0.0/8
                case 0x0b: return IP_SCOPE_PSEUDOPRIVATE;                             // 11.0.0.0/8 (US DoD)
                case 0x15: return IP_SCOPE_PSEUDOPRIVATE;                             // 21.0.0.0/8 (US DDN-RVN)
                case 0x16: return IP_SCOPE_PSEUDOPRIVATE;                             // 22.0.0.0/8 (US DISA)
                case 0x19: return IP_SCOPE_PSEUDOPRIVATE;                             // 25.0.0.0/8 (UK Ministry of Defense)
                case 0x1a: return IP_SCOPE_PSEUDOPRIVATE;                             // 26.0.0.0/8 (US DISA)
                case 0x1c: return IP_SCOPE_PSEUDOPRIVATE;                             // 28.0.0.0/8 (US DSI-North)
                case 0x1d: return IP_SCOPE_PSEUDOPRIVATE;                             // 29.0.0.0/8 (US DISA)
                case 0x1e: return IP_SCOPE_PSEUDOPRIVATE;                             // 30.0.0.0/8 (US DISA)
                case 0x2c: return IP_SCOPE_PSEUDOPRIVATE;                             // 44.0.0.0/8 (Amateur Radio)
                case 0x33: return IP_SCOPE_PSEUDOPRIVATE;                             // 51.0.0.0/8 (UK Department of Social Security)
                case 0x37: return IP_SCOPE_PSEUDOPRIVATE;                             // 55.0.0.0/8 (US DoD)
                case 0x38: return IP_SCOPE_PSEUDOPRIVATE;                             // 56.0.0.0/8 (US Postal Service)
                case 0x64:
                    if ((ip & 0xffc00000) == 0x64400000) return IP_SCOPE_SHARED;        // 100.64.0.0/10
                    break;
                case 0x7f: return IP_SCOPE_LOOPBACK;                                  // 127.0.0.0/8
                case 0xa9:
                    if ((ip & 0xffff0000) == 0xa9fe0000) return IP_SCOPE_LINK_LOCAL;    // 169.254.0.0/16
                    break;
                case 0xac:
                    if ((ip & 0xfff00000) == 0xac100000) return IP_SCOPE_PRIVATE;       // 172.16.0.0/12
                    break;
                case 0xc0:
                    if ((ip & 0xffff0000) == 0xc0a80000) return IP_SCOPE_PRIVATE;                // 192.168.0.0/16
                    break;
                case 0xff: return IP_SCOPE_NONE;                                      // 255.0.0.0/8 (broadcast, or unused/unusable)
            }
            switch(ip >> 28) {
                case 0xe: return IP_SCOPE_MULTICAST;                              // 224.0.0.0/4
                case 0xf: return IP_SCOPE_PSEUDOPRIVATE;                          // 240.0.0.0/4 ("reserved," usually unusable)
            }
            return IP_SCOPE_GLOBAL;
        }    break;

        case AF_INET6: {
            const unsigned char *ip = (const unsigned char *)(((const struct sockaddr_in6 *)ipAddr)->sin6_addr.s6_addr);
            if ((ip[0] & 0xf0) == 0xf0) {
                if (ip[0] == 0xff) return IP_SCOPE_MULTICAST;                              // ff00::/8
                if ((ip[0] == 0xfe)&&((ip[1] & 0xc0) == 0x80)) {
                    unsigned int k = 2;
                    while ((!ip[k])&&(k < 15)) ++k;
                    if ((k == 15)&&(ip[15] == 0x01))
                        return IP_SCOPE_LOOPBACK;                                              // fe80::1/128
                    else return IP_SCOPE_LINK_LOCAL;                                         // fe80::/10
                }
                if ((ip[0] & 0xfe) == 0xfc) return IP_SCOPE_PRIVATE;                       // fc00::/7
            }
            unsigned int k = 0;
            while ((!ip[k])&&(k < 15)) ++k;
            if (k == 15) { // all 0's except last byte
                if (ip[15] == 0x01) return IP_SCOPE_LOOPBACK;                              // ::1/128
                if (ip[15] == 0x00) return IP_SCOPE_NONE;                                  // ::/128
            }
            return IP_SCOPE_GLOBAL;
        }    break;

    }

    return IP_SCOPE_NONE;
}

