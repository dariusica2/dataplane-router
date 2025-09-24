#include <arpa/inet.h>
#include "string.h"

#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include "linked_list.h"
#include "trie.h"

#define ROUTE_TABLE_ENTRIES	100000

/* Ethernet types */
#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Trie used to keep track of the routing table entries */
trie_t *route_trie;

/* Mac table as simply linked list */
linked_list_t *arp_table;

/* Queue for packets awaiting MAC address */
queue arp_queue;

/* Structure used for the queued packets*/
typedef struct queued_packet {
	char buf[MAX_PACKET_LEN];
	size_t len;
	uint32_t next_hop;
	int interface;
} queued_packet;

/* Returns a pointer to the best matching route, or NULL if there
is no matching route (linear search through entire table) */
struct route_table_entry *get_best_route(uint32_t ip_dest) {

	struct route_table_entry *best_route = NULL;
	uint32_t best_mask = 0;

	for (int i = 0; i < rtable_len; i++) {
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix && rtable[i].mask > best_mask) {
			best_route = &rtable[i];
			best_mask = rtable[i].mask;
		}
	}

	return best_route;
}

/* Searches the trie for the best matching route, or NULL if there
is no matching route */
struct route_table_entry *get_best_route_trie(uint32_t ip_dest) {

	struct route_table_entry *best_route = NULL;
	trie_node_t *curr_node = route_trie->root;
	int curr_pos = 0;

	while (curr_node != NULL) {
		/* Memorising the last matching route (biggest mask) */
		if (curr_node->table_entry != NULL) {
			best_route = curr_node->table_entry;
		}

		/* Calculating the next bit in the address */
		uint8_t curr_bit = (ntohl(ip_dest) >> (31 - curr_pos)) & 1;
		curr_node = curr_node->children[curr_bit];
		curr_pos++;
	}

	return best_route;
}

/* Returns a pointer to the matching MAC address, or NULL if there
is no matching MAC address */
struct arp_table_entry *get_mac_from_arp(uint32_t given_ip) {

	ll_node_t *curr = arp_table->head;
	
	while (curr) {
		struct arp_table_entry *curr_entry = (struct arp_table_entry *)curr->data;
		if (curr_entry->ip == given_ip) {
			return curr_entry;
		}
		curr = curr->next;
	}

	return NULL;
}

/* Sends an ARP reply to a received request */
void send_arp_reply(char *recvd_packet, int interface) {

	/* Parsing received packet */
	struct ether_hdr *ethr_hdr_recv = (struct ether_hdr *)recvd_packet;
	struct arp_hdr *arp_hdr_recv = (struct arp_hdr *)(recvd_packet + sizeof(struct ether_hdr));

	/* Creating new ARP reply packet */
	char arp_reply[MAX_PACKET_LEN];
	struct ether_hdr *ethr_hdr_reply = (struct ether_hdr *)arp_reply;
	struct arp_hdr *arp_hdr_reply = (struct arp_hdr *)(arp_reply + sizeof(struct ether_hdr));

	/* Size of request */
	size_t arp_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);

	/* Setting up Ethernet header */
	get_interface_mac(interface, ethr_hdr_reply->ethr_shost);
	memcpy(ethr_hdr_reply->ethr_dhost, ethr_hdr_recv->ethr_shost, 6);
	ethr_hdr_reply->ethr_type = htons(ETHERTYPE_ARP);

	/* Setting up ARP header */
	arp_hdr_reply->hw_type = htons(1);
	arp_hdr_reply->proto_type = htons(ETHERTYPE_IP);
	arp_hdr_reply->hw_len = 6;
	arp_hdr_reply->proto_len = 4;
	arp_hdr_reply->opcode = htons(2);
	memcpy(arp_hdr_reply->shwa, ethr_hdr_reply->ethr_shost, 6);
	arp_hdr_reply->sprotoa = arp_hdr_recv->tprotoa;
	memcpy(arp_hdr_reply->thwa, ethr_hdr_reply->ethr_dhost, 6);
	arp_hdr_reply->tprotoa = arp_hdr_recv->sprotoa;

	/* Send ARP reply */
	send_to_link(arp_len, arp_reply, interface);
}

/* Sends an ARP request to the next hop IP in order to get its MAC address */
void send_arp_request(char *req_packet, struct route_table_entry *best_route) {

	/* Creating a new ARP request to send */
	char arp_request[MAX_PACKET_LEN];
	struct ether_hdr *ethr_hdr = (struct ether_hdr *)arp_request;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_request + sizeof(struct ether_hdr));

	/* Size of request */
	size_t arp_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);

	/* Setting up Ethernet header */
	get_interface_mac(best_route->interface, ethr_hdr->ethr_shost);
	memset(ethr_hdr->ethr_dhost, 0xFF, 6);
	ethr_hdr->ethr_type = htons(ETHERTYPE_ARP);

	/* Setting up ARP header */
	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(ETHERTYPE_IP);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1);
	get_interface_mac(best_route->interface, arp_hdr->shwa);
	inet_pton(AF_INET, get_interface_ip(best_route->interface), (void *)&arp_hdr->sprotoa);
	memset(arp_hdr->thwa, 0, 6);
	arp_hdr->tprotoa = best_route->next_hop;

	/* Send ARP request */
	send_to_link(arp_len, arp_request, best_route->interface);
}

void receive_arp_reply(struct arp_hdr *arp_hdr) {
	/* Adding the newly found MAC address in the ARP cache */
	struct arp_table_entry *new_arp_entry = malloc(sizeof(struct arp_table_entry));
	new_arp_entry->ip = arp_hdr->sprotoa;
	memcpy(new_arp_entry->mac, arp_hdr->shwa, 6);
	ll_add_nth_node(arp_table, 0, new_arp_entry);

	/* Checking if elements in queue need said MAC address */
	queue temp_queue = create_queue();

	while (!queue_empty(arp_queue)) {
		/* Dequeue packet */
		queued_packet *dequeued_packet = (queued_packet *)queue_deq(arp_queue);
		char *curr_buf = dequeued_packet->buf;
		size_t curr_buf_len = dequeued_packet->len;

		/* Check packet */
		struct ether_hdr *curr_ethr_hdr = (struct ether_hdr *)(curr_buf);

		/* If the packet needs the MAC address... */
		if (dequeued_packet->next_hop == new_arp_entry->ip) {
			/* ...complete said packet and send it off */
			memcpy(curr_ethr_hdr->ethr_dhost, new_arp_entry->mac, 6);
			send_to_link(curr_buf_len, curr_buf, dequeued_packet->interface);
			free(dequeued_packet);
		} else {
			/* If the packet doesn't need it, enqueue it back */
			queue_enq(temp_queue, dequeued_packet);
		}
	}

	while (!queue_empty(temp_queue)) {
		queue_enq(arp_queue, queue_deq(temp_queue));
	}
}

void icmp_echo_reply(char *old_packet, int interface, int len) {

	/* Parsing old packet */
	struct ether_hdr *old_ethr_hdr = (struct ether_hdr *)old_packet;
	struct ip_hdr *old_ip_hdr = (struct ip_hdr *)(old_packet + sizeof(struct ether_hdr));

	/* Creating a new packet to send */
	char new_packet[MAX_PACKET_LEN];
	struct ether_hdr *new_ethr_hdr = (struct ether_hdr *)new_packet;
	struct ip_hdr *new_ip_hdr = (struct ip_hdr *)(new_packet + sizeof(struct ether_hdr));
	struct icmp_hdr *new_icmp_hdr = (struct icmp_hdr *)((char *)new_ip_hdr + sizeof(struct ip_hdr));

	/* Copying contents of old packet */
	memcpy(new_packet, old_packet, MAX_PACKET_LEN);

	/* Switching MAC addresses around */
	memcpy(new_ethr_hdr->ethr_shost, old_ethr_hdr->ethr_dhost, 6);
	memcpy(new_ethr_hdr->ethr_dhost, old_ethr_hdr->ethr_shost, 6);

	/* Switching IP addresses around */
	new_ip_hdr->source_addr = old_ip_hdr->dest_addr;
	new_ip_hdr->dest_addr = old_ip_hdr->source_addr;
	/* Recomputing IP checksum */
	new_ip_hdr->checksum = 0;
	new_ip_hdr->checksum = checksum((uint16_t *)new_ip_hdr, sizeof(struct ip_hdr));

	/* Change ICMP type */
	new_icmp_hdr->mtype = 0;
	/* Recomputing ICMP checksum */
	new_icmp_hdr->check = 0;
	new_icmp_hdr->check = checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmp_hdr));

	/* Sending ICMP on interface which received packet */
	send_to_link(len, new_packet, interface);
}

/* Sends an appropriate ICMP packet based on icmp_code */
void icmp_error_handler(char *old_packet, int interface, int icmp_type) {

	/* Parsing old packet */
	struct ether_hdr *old_ethr_hdr = (struct ether_hdr *)old_packet;
	struct ip_hdr *old_ip_hdr = (struct ip_hdr *)(old_packet + sizeof(struct ether_hdr));

	/* Creating a new packet to send */
	char new_packet[MAX_PACKET_LEN];
	size_t new_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8;

	/* Ethernet header */
	struct ether_hdr *new_ethr_hdr = (struct ether_hdr *)new_packet;
	/* Source MAC */
	memcpy(new_ethr_hdr->ethr_shost, old_ethr_hdr->ethr_dhost, 6);
	/* Destination MAC */
	memcpy(new_ethr_hdr->ethr_dhost, old_ethr_hdr->ethr_shost, 6);
	/* Ethernet type */
	new_ethr_hdr->ethr_type = htons(ETHERTYPE_IP);

	/* IP header*/
	struct ip_hdr *new_ip_hdr = (struct ip_hdr *)(new_packet + sizeof(struct ether_hdr));
	new_ip_hdr->ihl = 5;
	new_ip_hdr->ver = 4;
	new_ip_hdr->tos = 0;
	new_ip_hdr->tot_len = htons((uint16_t)(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8));
	new_ip_hdr->id = htons(4);
	new_ip_hdr->frag = 0;
	new_ip_hdr->ttl = 69;
	new_ip_hdr->proto = 1;
	new_ip_hdr->checksum = 0;
	/* Source IP */
	inet_pton(AF_INET, get_interface_ip(interface), (void *)&new_ip_hdr->source_addr);
	/* Destination IP */
	new_ip_hdr->dest_addr = old_ip_hdr->source_addr;
	/* Calculate IP checksum */
	new_ip_hdr-> checksum = checksum((uint16_t *)new_ip_hdr, sizeof(struct ip_hdr));

	/* ICMP header*/
	struct icmp_hdr *new_icmp_hdr = (struct icmp_hdr *)((char *)new_ip_hdr + sizeof(struct ip_hdr));
	new_icmp_hdr->mtype = icmp_type;
	new_icmp_hdr->mcode = 0;
	new_icmp_hdr->check = 0;
	/* ICMP data (IP Header + 64 bits (8 bytes) of IP data)*/
	char *icmp_data = (char *)(new_icmp_hdr + sizeof(struct icmp_hdr));
	memcpy(icmp_data, old_ip_hdr, sizeof(struct ip_hdr) + 8);
	/* Calculate ICMP checksum */
	new_icmp_hdr->check = checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmp_hdr));

	/* Sending ICMP on interface which received packet */
	send_to_link(new_len, new_packet, interface);
}

/* Checks if a received address is valid */
int valid_ether_addr(struct ether_hdr *ethr_hdr, size_t interface) {

	/* Address which will be used for comparisons */
	uint8_t comp_addr[6];
	int router_flag = 1;
	int broadcast_flag = 1;

	/* First, the address of the interface */
	get_interface_mac(interface, comp_addr);
	for (int i = 0; i < 6; i++) {
		if (ethr_hdr->ethr_dhost[i] != comp_addr[i]) {
			router_flag = 0;
			break;
		}
	}

	/* Then the broadcasting address */
	memset(comp_addr, 0xFF, 6);
	for (int i = 0; i < 6; i++) {
		if (ethr_hdr->ethr_dhost[i] != comp_addr[i]) {
			broadcast_flag = 0;
			break;
		}
	}

	return router_flag | broadcast_flag;
}

int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	/* Setting up routing table */
	rtable = malloc(sizeof(struct route_table_entry) * ROUTE_TABLE_ENTRIES);
	DIE(rtable == NULL, "rtable malloc error");

	rtable_len = read_rtable(argv[1], rtable);

	/* Setting up trie */
	route_trie = trie_create();
	DIE(route_trie == NULL, "trie allocate error");

	for (int i = 0; i < rtable_len; i++) {
		trie_add_address(route_trie, &rtable[i]);
	}

	/* Setting up ARP table */
	arp_table = ll_create(sizeof(struct arp_table_entry));
	DIE(arp_table == NULL, "arp_table create error");

	/* Setting up queue for packets awaiting ARP replies */
	arp_queue = create_queue();
	DIE(arp_queue == NULL, "arp_queue create error");

	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    	/* Packets received are in network order, any header field which has
		more than 1 byte will need to be conerted to host order. For example,
		ntohs(eth_hdr->ether_type). The oposite is needed when sending a packet
		on the link, */

		/* Parsing ethernet header */
		struct ether_hdr *ethr_hdr = (struct ether_hdr *)buf;

		/* Validating packet address */
		if (!valid_ether_addr(ethr_hdr, interface)) {
			continue;
		}

		/* Checking whether it's an IPv4 or ARP header */
		/* ARP */
		if (ethr_hdr->ethr_type == htons(ETHERTYPE_ARP)) {
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			/* Checking if it is... */
			if (arp_hdr->opcode == ntohs(1)) {
				/* ...an ARP request... */
				send_arp_reply(buf, interface);
			} else if (arp_hdr->opcode == ntohs(2)) {
				/* ...or an ARP reply */
				receive_arp_reply(arp_hdr);
			}

			continue;
		}

		/* IPv4 */
		if (ethr_hdr->ethr_type == htons(ETHERTYPE_IP)) {
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			/* Verifying destination */
			uint32_t interface_ip;
			inet_pton(AF_INET, get_interface_ip(interface), (void *)&interface_ip);

			if (ip_hdr->dest_addr == interface_ip) {
				/* Check if it is an ICMP request */
				if (ip_hdr->proto == 1) {
					struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr + sizeof(struct ip_hdr));
					if ((icmp_hdr->mtype) == 8 && (icmp_hdr->mcode == 0)) {
						/* Respond to an ICMP message */
						icmp_echo_reply(buf, interface, len);
					}
				}
				continue;
			}

			/* Verify checksum */
			uint16_t prev_checksum = ip_hdr->checksum;
			ip_hdr->checksum = 0;
			uint16_t curr_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));
			if (prev_checksum != htons(curr_checksum)) {
				continue;
			}

			/* Verifying and updating TTL */
			uint8_t prev_ttl = ip_hdr->ttl;
			if (ip_hdr->ttl <= 1) {
				/* Send a "Time exceeded" ICMP message to source */
				icmp_error_handler(buf, interface, 11);
				continue;
			}
			ip_hdr->ttl--;

			/* Search in routing table */
			struct route_table_entry *best_route = get_best_route_trie(ip_hdr->dest_addr);
			if (best_route == NULL) {
				/* Send a "Destination unreachable" ICMP message to source */
				icmp_error_handler(buf, interface, 3);
				continue;
			}

			/* Update checksum */
			uint16_t next_checksum = ~(~prev_checksum +  ~((uint16_t)prev_ttl) + (uint16_t)ip_hdr->ttl) - 1;
			ip_hdr->checksum = next_checksum;

			/* Rewrite L2 addresses */
			get_interface_mac(best_route->interface, ethr_hdr->ethr_shost);

			/* Looking for the MAC address of the next hop IP address in the ARP cache */
			struct arp_table_entry *arp_entry = get_mac_from_arp(best_route->next_hop);

			/* If the MAC address is not in the ARP cache... */
			if (arp_entry == NULL) {
				/* ...the packet is queued... */
				queued_packet *packet_copy = malloc(sizeof(queued_packet));
				memcpy(packet_copy->buf, buf, len);
				packet_copy->len = len;
				packet_copy->next_hop = best_route->next_hop;
				packet_copy->interface = best_route->interface;
				queue_enq(arp_queue, packet_copy);

				/* ...and an ARP request is generated */
				send_arp_request(buf, best_route);
				continue;
			}
			memcpy(ethr_hdr->ethr_dhost, arp_entry->mac, 6);

			/* Sending new packet on next hop interface */
			send_to_link(len, buf, best_route->interface);
		}
	}
}
