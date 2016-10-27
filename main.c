/* Under the GNU license*/

#include "memoryman.h"
#include <ncurses.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "gateway.h"
#include "net_headers.h"
#include "user.h"

/*
TO DO LIST
-Add columns to the DNS listings
-Add next and prev for DNS listings
-Add VLAN Support
-Add IP6 Protocol support
#-Add DNS Support

Bug list:
-Sometimes it doesn't sort?

-lnet?
*/

#ifdef DEBUG
#define ASSERT(x,y) if(x){ deinit();printf("Assert!\nLine number #%i\n%s\n",__LINE__,y);exit(0);}
#else
#define ASSERT(x,y) if(x){ deinit();printf("%s\n",y);exit(0);}
#endif
#include <stdlib.h>

#define MAX_IP 256

enum { MAIN,OPTIONS,SITES };

struct Users* users=NULL; 
int init_pcap(char* eth);
inline void init();
inline void deinit();
inline void Add(int id,u_char* macaddress,u_char* userIP,unsigned char* pload,int bytes,bool hasDNS);
inline void got_packet(struct pcap_pkthdr *header, u_char *packet);
inline void store_packages(pcap_t *handle);
inline void write_to_screen();
inline bool isOnList(char* macAddr);
inline bool MaskWithGateway(char* ipAddress);
inline struct User_info* FindByIP(char* ip);
inline void TcpKill(char* ip);
inline void sortTopUsers();
inline struct User_info* FindByID(int id);
inline bool isOnTopList(char* ip);
inline void GetDNS(u_char* payload,struct Users_info* userinformation);
inline int FindCharInString(char charToFind, char* string);
inline void GetStringRange(char* string, int start, int end, char* output);
inline int CountChar(char charToCount, char* string);
inline bool DNSDuplicateCheck(struct Users_info* user, unsigned char* DNSName);

struct Users_info* userInfo=NULL;
const int MAC_ADDRESS_LEN=6;
int* topUsers[15];
int topUserCount=0;
pthread_t packet_capture={0}; 
int quit = 0;
struct in_addr gateway={0};
int newID=0;
char dev[256]={0};
int y=0;
bool nextKey=false;
char killInput[255]={0};
int killInputCount=0;
int listIndex=0;
int topUserIndex=0;
bool hasTopFive=false;
int show=10;
bool optionScr=FALSE;
FILE* dnsFile=NULL;
int screen_status=MAIN;
int maxDNSNameCount=20;
int DNSPage=0;
char *defaultGateway=NULL;

int main(int argc, char **argv)
{
	char* eth=NULL;
	struct Users_info* tempNode=NULL;
	stdscr=NULL;

	init();

	if (argc == 2)
	{
		ASSERT(strlen(argv[1]) > 200,"Error device name  Length is too long!\n");

		eth = (char*) malloc(256);
		
		ASSERT(eth==NULL,"Error Can not allocate memory");
		ASSERT(strlen(argv[1]) > 250, "Error string too long!");

		strcpy(eth,argv[1]);
	} else {
		/*
		Parse all parameters*/
		for (int i=0; i < argc; i++)
		{
			if (strcmp("-i", argv[i]) == 0)
			{
				if (i != argc)
				{
					eth = (char*) malloc(256);
					strcpy(eth,argv[i+1]);
				}
			}
			//Gateway
			if (strcmp("-g",argv[i]) == 0)
			{
				if (i != argc)
				{
					defaultGateway = (char*) malloc(256);
					strcpy(defaultGateway,argv[i+1]);
				}
			}

		}
	}
	
	if (defaultGateway == NULL)
	{
		defaultGateway = (char*) malloc(256);
		strcpy(defaultGateway,"192.168.1.1");
	}

	ASSERT(init_pcap(eth) == 0,"Error unable to init pcap");

	if (eth != NULL)
	{
		free(eth);
		eth=NULL;
	}
	deinit();
	return 0;
}

void init()
{
	int i=0;
	users = (struct Users*) malloc(sizeof(struct Users));
	memset(users, 0,sizeof(struct Users));
	ASSERT(users == NULL,"Error can not allocate memroy");
	users->head = NULL;
	users->current=NULL;

	for (i=0;i<15;i++)
	{
		topUsers[i] = NULL;
	}
}

void deinit()
{
	if (stdscr!=NULL)
	{
		endwin();
	}
	
	freeall();
	return ;

	struct Users_info* currentNode = users->head;

	while (currentNode != NULL)
	{
		struct Users_info* temp = currentNode;
		currentNode = currentNode->next;
		if (temp != NULL)
		{
			if (temp->dnsInfo != NULL)
			{
				struct dns_info* dnsHeader = temp->dnsInfo->head;
				while (dnsHeader != NULL)
				{
					if (dnsHeader->name != NULL)
					{
						free(dnsHeader->name);
						dnsHeader->name = NULL;
					}
					struct dns_info* tempDNS = dnsHeader;
					dnsHeader = dnsHeader->next;
					if (tempDNS != NULL)
					{
						free(tempDNS);
						tempDNS=NULL;
					}
				}
				free(temp->dnsInfo);
				temp->dnsInfo=NULL;
			}
			free(temp);
			temp=NULL;
		}
	}

	if (users != NULL)
	{
		free(users);
		users=NULL;
	}
	freeall();
}

void AddDNS(struct Users_info* user, unsigned char* dnsName)
{
	if (user != NULL)
	{
		if (user->dnsInfo != NULL)
		{
			if (user->dnsInfo->head == NULL)
			{
				struct dns_info* newDnsInfo = (struct dns_info*) malloc(sizeof(struct dns_info));
				newDnsInfo->name = (unsigned char*) malloc(strlen(dnsName)+1);

				ASSERT(newDnsInfo==NULL,"Error can not allocate memory");
				strcpy(newDnsInfo->name,dnsName);
				newDnsInfo->next = NULL;
				user->dnsInfo->head = newDnsInfo;
				user->dnsInfo->current = newDnsInfo;

			} else {
				struct dns_info* newDnsInfo = (struct dns_info*) malloc(sizeof(struct dns_info));
				ASSERT(newDnsInfo==NULL,"Error can not allocate memory");
				newDnsInfo->name = (unsigned char*) malloc(strlen(dnsName)+1);
				strcpy(newDnsInfo->name,dnsName);
				newDnsInfo->next = NULL;
				user->dnsInfo->current->next = newDnsInfo;
				user->dnsInfo->current = user->dnsInfo->current->next;
			}

			if (user)
			{
				user->dnsInfo->total++;
			}
		}
	}
}

bool DNSDuplicateCheck(struct Users_info* user, unsigned char* DNSName)
{
	if (user == NULL) return false;
	if (user->dnsInfo == NULL) return false;

	struct dns_info* llhead = user->dnsInfo->head;

	while (llhead != NULL)
	{
		if (strcmp(llhead->name, DNSName) == 0)
		{
			return true;
		}
		llhead = llhead->next;
	}
	return false;
}

void Add(int id,u_char* macaddress,u_char* userIP,unsigned char* pload,int bytes,bool hasDNS)
{
	#if 1
	if (users->head == NULL)
	{
		users->head = malloc(sizeof(struct Users_info));
		ASSERT(users->head==NULL,"Error can not allocate memory");
		users->head->next=NULL;
		users->head->id = id;
		users->head->size=bytes;
		users->head->bytes=bytes;
		users->head->busychar='\0';
		users->head->dnsInfo = (struct lldns_info*) malloc(sizeof(struct lldns_info));
		users->head->dnsInfo->head = NULL;
		users->head->dnsInfo->current = NULL;
/*
		int i=0;
		
		for (i=0;i<ETHER_ADDR_LEN;i++)
		{
			users->head->macaddress[i] = '\0';
		}

		int j=0;
		
		for (j=0;j < 255;j++)
		{
			users->head->userip[j] = '\0';
		}

		if (strlen(macaddress) < 100)
		{
			strcpy(users->head->macaddress,macaddress);
		}

		if (strlen(userIP) < 200)
		{
			strcpy(users->head->userip,userIP);
		}
		*/
		//strcpy(users->head->macaddress,macaddress);
		strcpy(users->head->userip,userIP);
		users->current = users->head;

	} else {
		
		struct Users_info* newUsers = malloc(sizeof(struct Users_info));
		ASSERT(newUsers==NULL,"Error can not allocate memory\n");
		newUsers->id = id;
		newUsers->size=bytes;
		newUsers->bytes=bytes;
		newUsers->busychar='\0';
		newUsers->dnsInfo = (struct lldns_info*) malloc(sizeof(struct lldns_info));
		newUsers->dnsInfo->head = NULL;
		newUsers->dnsInfo->current = NULL;
		/*
		int i=0;
		for (i=0;i<ETHER_ADDR_LEN;i++)
		{
			newUsers->macaddress[i] = '\0';
		}

		int j=0;
		for (j=0;j < 255;j++)
		{
			newUsers->userip[j] = '\0';
		}

		ASSERT(strlen(macaddress) > 100,"Error Mac Address is too long");
		strcpy(newUsers->macaddress,macaddress);


		ASSERT(strlen(userIP) > 200,"Error user IP is too long");
		strcpy(newUsers->userip, userIP);
		*/

		//strcpy(newUsers->macaddress,macaddress);
		strcpy(newUsers->userip, userIP);
		users->current->next = newUsers;
		users->current = users->current->next;
		users->current->next = NULL;
	}

	topUserCount++;
	#endif
}

int init_pcap(char* eth)
{
	char netmask[256]={0};
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle=NULL;
	char filter_exp[] = "";
	struct bpf_program fp={0};
	bpf_u_int32 mask=0;
	bpf_u_int32 net=0;

	if (eth==NULL)
	{
		ASSERT(!GetDefaultGateway(netmask,dev),"Error unable to get net mask")
	} else {
		ASSERT(strlen(eth) > 200,"Error device name is too long")
		strcpy(dev,eth);
	}

	ASSERT(pcap_lookupnet(dev, &net, &mask, errbuf) == -1,"Error Can't not look up device");

	handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);

	ASSERT(handle == NULL,"Couldn't open device");

	ASSERT(pcap_datalink(handle) != DLT_EN10MB,"Error not an Ethernet device!");

	ASSERT(pcap_compile(handle, &fp, filter_exp, 0, net) == -1 , "Error: Couldn't parse filter!" );

	ASSERT(pcap_setfilter(handle, &fp) == -1, "Error Could not install filter!"  );

	gateway.s_addr = net;

	ASSERT(pthread_create( &packet_capture, NULL,  (void * (*)(void *)) store_packages, handle) != 0,"Error can not create thread!")
	pthread_join( packet_capture, NULL); 

	return 1;
}

void got_packet(struct pcap_pkthdr *header, u_char *packet)
{
	struct sniff_ethernet *ethernet=NULL;  /* The ethernet header [1] */
	struct sniff_ip *ip=NULL;              /* The IP header */
	struct sniff_tcp *tcp=NULL;            /* The TCP header */
	int size_ip=0;
	int size_tcp=0;
	int size_payload=0;
	int no_error=1;
	u_char* payload=NULL;
	char src_ip[255]={0};
	char  dst_ip[255]={0};

	ethernet = (struct sniff_ethernet*)(packet);

	if (ethernet->ether_type == VLAN)
	{
		
	} else 
	if (ethernet->ether_type == IPV4)
	{
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

		//Accepts only tcp and udp
		if (ip->ip_p != TCP && ip->ip_p !=UDP )
		{
			return ;
		}
		if (ip != NULL && ip!=0 )
		{
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20 && no_error == 0) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}
		}

		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

		if (tcp != 0) 
		{
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20 && no_error == 0) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
		}

		if (ip != 0)
		{
			payload = (u_char*)(packet+SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			strcpy(src_ip,inet_ntoa(ip->ip_src));
			strcpy(dst_ip,inet_ntoa(ip->ip_dst));

			char* theGateway = inet_ntoa(gateway);

			if (size_payload > 0)
			{
				if (isOnList(src_ip))
				{
					if (MaskWithGateway(src_ip))
					{
						struct Users_info* userinformation = FindByIP(src_ip);
						
						if (userinformation != NULL)
						{
							if (userinformation->busychar == '\\')
							{
								userinformation->busychar = '/';
							} else {
								userinformation->busychar = '\\';
							}

							userinformation->bytes += size_payload;
							if (ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) == 53)
							{
								GetDNS(payload,userinformation);
							}
							return ;
						}
						
					}
				} else {

					if (MaskWithGateway(src_ip))
					{
						//Add ip to the list
						if (ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) == 53)
						{
							Add(newID,ethernet->ether_shost,src_ip,payload,size_payload,TRUE);
						}else {
							Add(newID,ethernet->ether_shost,src_ip,payload,size_payload,FALSE);
						}
						newID++;
						return ;
					}
				}

				if (isOnList(dst_ip))
				{
					if (MaskWithGateway(dst_ip))
					{
						struct Users_info* userinformation = FindByIP(dst_ip);
						if (userinformation != NULL)
						{
							if (userinformation->busychar == '\\')
							{
								userinformation->busychar = '/';
							} else {
								userinformation->busychar = '\\';
							}
							userinformation->bytes += size_payload;

							#if 0
							if (ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) == 53)
							{
								GetDNS(payload,userinformation);
							}
							#endif

							return ;
						}
					}
				} else {
					if (MaskWithGateway(dst_ip))
					{
						//Add to list
						if (ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) == 53)
						{
							Add(newID,ethernet->ether_dhost,dst_ip,payload,size_payload,TRUE);
						}else {
							Add(newID,ethernet->ether_dhost,dst_ip,payload,size_payload,FALSE);
						}
						newID++;
						return ;
					}
				}
			}
		}
	} else
	/*Note: ipv6 packet parsing needs to be done here*/
	if (ethernet->ether_type == IPV6)
	{
		//IPV6
	}
	return;
}

struct User_info* FindByID(int id)
{
	struct Users_info* current_User = users->head;
	
	while(current_User != NULL)
	{
		if (current_User)
		{
			if (current_User->id == id)
			{
				return current_User;
			}
			current_User=current_User->next;
		}
	}
	return NULL;
}

struct User_info* FindByIP(char* ip)
{
	struct Users_info* current_User = users->head;
	
	while(current_User != NULL)
	{
		if (current_User)
		{
			if (current_User->userip)
			{
				if (strcmp(current_User->userip,ip) == 0)
				{
					return current_User;
				}
			}
			current_User=current_User->next;
		}
	}
	return NULL;
}


void store_packages(pcap_t *handle)
{
	int code=0;
	struct pcap_pkthdr *header=NULL;               
	u_char *packet=NULL;  

	initscr();
	noecho();
	nodelay(stdscr, TRUE);

	while(quit==0)
	{
		
		code = pcap_next_ex(handle,&header,&packet);
		if (code == 1)
		{
			if (header != NULL)
			{
				got_packet(header, packet);
			}
		}
		write_to_screen();
	}
}

void write_to_screen()
{
	int key=-1;

	switch (screen_status)
	{
		case MAIN:
			{
				struct Users_info* current_User = users->head;
				y=1;
				mvprintw(0,1,"IP Address");
				mvprintw(0,20,"Mac Address");
				mvprintw(0,45,"Recieved");
				mvprintw(0,60,"ID");

				//sortTopUsers(); 
				if (hasTopFive == true)
				{
					int i=0;
					for (i=0;i<show;i++)
					{
						struct Users_info* user = (struct Users_info*) topUsers[i];

						int macAddressX = 20;
#if 1
						int j=0;
						for (j=0;j < MAC_ADDRESS_LEN;j++)
						{
							mvprintw(y,macAddressX,"%x", user->macaddress[j]);
							if (j < MAC_ADDRESS_LEN-1)
							{
								mvprintw(y,macAddressX+2,":");
							}
							macAddressX +=3;
						}
#endif
						mvprintw(y,1,"%s", user->userip);
						if (user->bytes  < 1048576)
						{
							mvprintw(y,45,"%i bytes", user->bytes);
						} else {
							mvprintw(y,45,"%i MB", user->bytes/1048576);
						}

						clrtoeol();

						mvprintw(y,60,"%i",user->id);


						mvprintw(y,75,"%c",user->busychar);
						clrtoeol();
						y++;

					} 
					refresh();
				}else {
					//Display but doesn't sort until max number is reached
					while (current_User)
					{
						int macAddressX = 20;
						int j=0;
#if 1
						for (j=0;j < MAC_ADDRESS_LEN;j++)
						{
							mvprintw(y,macAddressX,"%x", current_User->macaddress[j]);
							if (j < MAC_ADDRESS_LEN-1)
							{
								mvprintw(y,macAddressX+2,":");
							}
							macAddressX +=3;
						}
#endif
						mvprintw(y,1,"%s", current_User->userip);
						if (current_User->bytes  < 1048576)
						{
							mvprintw(y,45,"%i bytes", current_User->bytes);
						} else {
							mvprintw(y,45,"%i MB", current_User->bytes/1048576);
						}

						clrtoeol();

						mvprintw(y,60,"%i",current_User->id);


						mvprintw(y,75,"%c",current_User->busychar);
						clrtoeol();
						y++;

						current_User = current_User->next;
					}
				}

				mvprintw(show+2,5,"Press Q to quit or i for more information.");

				key = getch();
				if (key == 'q') quit=1;

				if (key == 'i' && nextKey == false)
				{
					nextKey=true;
					return ;
				} 

				if (nextKey)
				{
					mvprintw(show+3,10,"input: %s", killInput);
				}

				if (nextKey)
				{

					if (key >= '0' && key <= '9' && killInputCount < 20)
					{
						killInput[killInputCount] =  key;
						killInputCount++;
						killInput[killInputCount] = '\0';
					} else {
						if (key == '\n') 
						{ 
							int killID = atoi(killInput);

							if (killID < topUserCount)
							{
								clear(); 
								screen_status=OPTIONS; 
								userInfo = FindByID(killID);
							} else {
								int i=0;
								for (i=0;i<killInputCount;i++)
								{
									killInput[i] = '\0';
								}
								killInputCount=0;

								nextKey=false;
							}

							mvprintw(show+3,10,"      ");
							clrtoeol();
						} 
					}
				}
				break;
			}
		case OPTIONS:
		{
			mvprintw(1,1,"option screen");
			mvprintw(3,1,"s Show DNS Requests");
			mvprintw(4,1,"k Engage Tcpkill");
			mvprintw(6,1,"b Go back to the option screen");

			key = getch();
			if (key == 's')
			{
				clear();
				refresh();
				screen_status=SITES;
				key = '\0';
			}

			if (key == 'q') quit=1;
			if (key == 'b') 
			{
				clear();
				refresh();
				screen_status=MAIN;
				int i=0;
				for (i=0;i<killInputCount;i++)
				{
					killInput[i] = '\0';
				}
				killInputCount=0;

				nextKey=false;
				return ;
			}


			break;
		}
		case SITES:
		{
			mvprintw(1,1,"DNS Requestes (press b to go back and n for the next %i bunch, p for the prev %i bunch)",maxDNSNameCount,maxDNSNameCount );
			key = getch();

			if (key == 'b')
			{
				DNSPage = 0;
				clear();
				refresh();
				screen_status=OPTIONS;
				key = '\0';
				break;
			}

			if (key == 'n')
			{
				/* NOTE: This need fixin'*/
				//if (DNSPage > userInfo->dnsInfo->total )
				//{
				//if (DNSPage < maxDNSNameCount)
				//{
					clear();
					refresh();
					key = '\0';

					DNSPage+=maxDNSNameCount;
				//}
				//}
			}
			if (key == 'p')
			{
				if (DNSPage >= 0 )
				{
					clear();
					refresh();
					key = '\0';

					DNSPage-=maxDNSNameCount;
				}
			}
			if (userInfo != NULL)
			{
				if (userInfo->dnsInfo != NULL)
				{
					if (userInfo->dnsInfo->head != NULL)
					{
						struct dns_info* tempNode = userInfo->dnsInfo->head;
						int y=2;
						int ucount=0;
						int i=0;

						if (userInfo->dnsInfo->total > maxDNSNameCount)
						{
							int j=0;
							for (j=0;j<DNSPage;j++)
							{
								if (tempNode != NULL)
								{
									tempNode = tempNode->next;
								}
							}
						}

						for (i=0;i<maxDNSNameCount;i++)
						{
						
							if (tempNode->name != NULL)
							{
								mvprintw(y,3,"%i. %s",i+1,tempNode->name);
								y++;
							}

							ucount++;
							
							tempNode = tempNode->next;
							if (tempNode == NULL) break;
						}
					}
				}
			}
			break;
		}
	}
	refresh();
}

bool isOnList(char* ipAddr)
{
	struct Users_info* current_User = users->head;

	while(current_User != NULL)
	{
		if (strcmp(current_User->userip,ipAddr) == 0)
		{
			return true;
		}
		current_User=current_User->next;
	}
	return false;
}

bool MaskWithGateway(char* ipAddress)
{
	char* fakeIPMask = ipAddress;
	int i=0;

	int maskIPs[MAX_IP]={};
	int userIP[MAX_IP]={};

	int maskIPCount=0;
	int userIPCount=0;

	int tempCount=0;
	int gwTempCount=0;
	//NOTE(NDS) This is a CHAR NOT A INT YOU DUMBASS!!
	char gwTemp[MAX_IP] = {};
	int count=0;
	char temp[MAX_IP]={};
	char* myGateway = NULL;


	myGateway = malloc(256);
	memset(myGateway, '\0',255);
	strcpy(myGateway,defaultGateway);

	for (i=0;i<strlen(myGateway);i++)
	{	
		if (myGateway[i] == '.')
		{
			gwTemp[gwTempCount] = '\0';
			temp[count] = '\0';
					
			unsigned int n1 = atoi(temp);
			unsigned int n2 = atoi(gwTemp);

			if ( (n1  ^ n2)  != 0)
			{
				return false;
			}
			
			count = 0;
			gwTempCount=0;
		} else {
			temp[count] = ipAddress[i];
			count++;
			gwTemp[gwTempCount] = myGateway[i];
			gwTempCount++;
		}
	}
	return true;
}


void sortTopUsers()
{
	//add the first five into the array
	if (topUserCount == show && hasTopFive == false)
	{
		int i=0;

		struct Users_info* current_User = users->head;

		while (i != show || current_User != NULL)
		{
			topUsers[i] = (int*) current_User;
			current_User = current_User->next;
			i++;
		}

		int j=0;
		//sort
		for (j=0;j<show;j++)
		{
			int k=0;
			for (k=0;k<show;k++)
			{
				if (k!=j)
				{
					struct Users_info* firstUser =  (struct Users_info*) topUsers[k];
					struct Users_info* secondUser = (struct Users_info*) topUsers[j];

					if (firstUser->bytes < secondUser->bytes)
					{
						struct Users_info* temp = secondUser;
						topUsers[j] = topUsers[k];
						topUsers[k] = temp;
					}
				}
			}
		}

		topUserIndex = show;
		listIndex = show;
		hasTopFive = true;

	} else 
	if (topUserCount > show)
	{
		
		struct Users_info* current_User = users->head;
		struct Users_info* lastTopUser = (struct Users_info*) topUsers[topUserIndex-1];

		int i=0;

		while (current_User != NULL)
		{
			if (isOnTopList(current_User->userip) == false)
			{
				if (current_User->bytes > lastTopUser->bytes)
				{
					topUsers[topUserIndex-1] = (int*) current_User;
				}
				
				listIndex++;
			}
			current_User = current_User->next;
		}

		int j=0;
		//sort
		for (j=0;j<show;j++)
		{
			int k=0;
			for (k=0;k<show;k++)
			{
				if (k!=j)
				{
					struct Users_info* firstUser =  (struct Users_info*) topUsers[k];
					struct Users_info* secondUser = (struct Users_info*) topUsers[j];

					if (firstUser->bytes < secondUser->bytes)
					{
						struct Users_info* temp = secondUser;
						topUsers[j] = topUsers[k];
						topUsers[k] = temp;
					}
				}
			}
		}
	}
}


bool isOnTopList(char* ip)
{
	int i=0;
	for (i=0;i<show;i++)
	{
		struct Users_info* topUser = (struct Users_info*) topUsers[i];
		if (strcmp(topUser->userip,ip) == 0)
		{
			return true;
		}
	}

	return false;
}

void GetDNS(u_char* payload,struct Users_info* userinformation)
{
	int p=0;
	struct udp_header* udpheader = (struct udp_header*) payload;
	struct dns_header* dnsheader = (struct dns_header*) (payload+1+sizeof(struct udp_header));
	unsigned char newDNSOutput[1028];

	if (dnsheader->questions > 0)
	{
		for (p=0;p<strlen(dnsheader->questions);p++)
		{
			if (dnsheader->questions[p] != 0 && dnsheader->questions[p] < 31 && dnsheader->questions[p] < 125)
			{
				dnsheader->questions[p] = '.';
			} 
		}
		dnsheader->questions[p] = '\0';

		if ( CountChar('.', dnsheader->questions) > 1 )
		{
			int dotPlacement = FindCharInString('.', dnsheader->questions);

			if (dotPlacement != -1)
			{
				GetStringRange(dnsheader->questions,dotPlacement+1, strlen(dnsheader->questions),newDNSOutput);
			}

			if (DNSDuplicateCheck(userinformation,&newDNSOutput) == false )
			{
				AddDNS(userinformation,&newDNSOutput);
			}
		} else {
			if (DNSDuplicateCheck(userinformation,dnsheader->questions) == false )
			{
				AddDNS(userinformation,dnsheader->questions);
			}
		}
	}
}

int CountChar(char charToCount, char* string)
{
	int i=0;
	int count=0;
	for (i=0;i<strlen(string);i++)
	{
		if (charToCount == string[i] )
		{
			count++;
		}
	}
	return count;
}

int FindCharInString(char charToFind, char* string)
{
	int i=0;

	for (i=0;i<strlen(string);i++)
	{
		if (charToFind == string[i])
		{
			return i;
		}
	}
	return -1;
}

void GetStringRange(char* string, int start, int end, char* output)
{
	int i=0;
	int j=0;

	for (i=start;i<end;i++)
	{
		output[j] = string[i];
		j++;
	}
	output[j] = '\0';
}
