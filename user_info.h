#ifndef USER_INFO_H
#define USER_INFO_H


struct dns_info
{
	char* name;
	struct dns_info* next;
};

struct lldns_info
{
	int total;
	struct dns_info* head;
	struct dns_info* current;
};

struct Users_info
{
	int id;
	u_char macaddress[ETHER_ADDR_LEN];
	u_char userip[256];
	int size;
	int bytes;
	struct Users_info* next;
	char busychar;
	struct lldns_info *dnsInfo;
};

#endif
