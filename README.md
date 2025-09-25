# Communications Protocols

## Assignment 1 - Dataplane Router

### Requirements solved:

- Routing process (IPv4)
- Efficient Longest Prefix Match (implementation with Trie)
- ARP protocol
- ICMP protocol

***

Solved the requirements in the following order:

1. Routing process
2. ICMP protocol
3. ARP protocol
4. Efficient Longest Prefix Match

***

### Routing process

This is addressed directly in the main function, meaning that the packet is sent
from main with the help of the send_to_link function.
However, before that, several steps are performed.
The routing table is read, the Trie is created in which the entries from the routing
table will be kept, and the ARP cache is created.
The received packet is modified in-place, that is, a new packet is not created to
make the changes. Information is rewritten from the initial stream of bytes received
in buf, and this is subsequently sent further.

### ICMP protocol

It is implemented using two functions, namely icmp_error_handler and icmp_echo_reply.
- icmp_error_handler receives the error type (icmp_type) and creates a new
packet to signal this error
- icmp_echo_reply also creates a new packet, but its content is copied from the initial
- received packet and only certain fields are changed (the source and destination
addresses and the type in the ICMP header).

### ARP Protocol

The ARP cache is maintained as a single linked list.
This protocol is based on 3 functions, namely send_arp_request, send_arp_reply
and receive_arp_reply.
- send_arp_request is called when a MAC address is not found in the ARP cache, and
  a call to the IP address of the next hop is needed to find it. At the same time, the
  packet waiting for the MAC address is put into a queue, storing the packet content,
  length, next hop, and interface on which to send it.
- send_arp_reply is called when the router receives a request and simply sends the MAC
  address of the interface on which the request was sent.
- receive_arp_reply has several roles. First, it adds the new entry to the ARP cache.
  Then, it checks all the packets in the queue and their next hop IP address. If it is
  the same as the IP address that was just entered into the table, then the packets are
  completed and sent on. The rest of the packets are put into a temporary queue, and after
  the initial ARP queue is empty, it receives all the elements from the temporary queue back.

### Efficient Longest Prefix Match (with Trie)

A Trie is used to hold the entries in the routing table. Each node in the Trie has two
copies, one for bits 0 and one for bits 1. Each entry in the table has a mask and a prefix,
which are the basis for encoding the entry in the Trie. The mask represents how many bits of
the prefix are encoded.

An example is "01000101"
From the root, the first bit (from the left) is 0, then 1, etc. The mask starts at 0
and increases as the bits are encoded (0000 -> 1000 -> 1100 -> ...), and
when it is the same as the one in the routing table entry, the value in the
node becomes the respective entry in the table.

When searching, the tree is "descended", and the last entry in the routing table is kept,
since it corresponds to a longer mask.
