#include "radiotap.h"
#include "ieee80211.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#define PORT 8888



void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void channel_hopper();


typedef struct device{
	uint8_t address[6];
	int count;
	struct device *next;
}device ;


void channel_hopper(){
	int channel;
	char str[24];
	srand(time(NULL));
	while (1){
		sprintf(str, "iw dev mon0 set channel %d", channel);
		system("ifconfig wlan0 down");
		sleep(1);
		system(str);
		//system(" ip link set dev wlan0 up");
		system("iwlist mon0 channel");
		sleep(0.5);
		channel = (rand() % 11) + 1;
	}
}


pthread_t hopper;
device *devices;
int sniffed_devices = 0;

int main(int argc, char ** argv){


	pthread_create(&hopper, NULL, channel_hopper, NULL);
	char device[] = "mon0";
	char *errbuf;
	int linktype;

	printf("Monitoring interface: %s\n", device);

	pcap_t *handle;
	handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf);  //3000 ms buffer timeout


	if(handle==NULL){ printf("ERRO: %s\n", errbuf); }

	if((linktype = pcap_datalink(handle)) < 0){
		printf("pcap_datalink(): %s\n", pcap_geterr(handle));
		return -1;
	}

	printf("Starting capture loop\n");
	pcap_loop(handle, 0, packetHandler, NULL);


	printf("\n");
	//loop para exibicao dos dispositivos encontrados
	while(devices!=NULL){
		printf("%02x:%02x:%02x:%02x:%02x:%02x  -- count=%d\n", devices->address[0],
                	                                  devices->address[1],
                        	                          devices->address[2],
                                	                  devices->address[3],
                                        	          devices->address[4],
                                                	  devices->address[5],
							  devices->count);
		devices = devices->next;
	}

	return 0;


}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){


	int is_beacon = 0;
	char hostname[10];
	hostname[9] = '\0';
	gethostname(hostname, 10);
	int socket_desc;  //socket descriptor
	socket_desc = socket(AF_INET, SOCK_DGRAM,IPPROTO_UDP);  //AF_INET = IPV4  --  SOCK_STREAM = TCP
	if(socket_desc == -1) printf("Could not create socket");
	struct sockaddr_in server;
	int server_struct_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = inet_addr("192.168.0.127");


	struct ieee80211_radiotap_header *rthdr;
	rthdr = (struct ieee80211_radiotap_header *) packet;
	uint8_t *type_subtype = (uint8_t *) packet + rthdr->it_len;

	/*Os 2 bits menos significativos do campo type_subtype identificam o protocolo (sempre 00), os 2 seguintes
	representam o tipo (00:management, 01:control, 10:data) e os 4 ,mais significativos o subtipo.
	por isso o if abaixo filtra os numeros invalidos(00001100) */
        if ((*type_subtype & 12) == 12){
                printf("Not an ieee802.11 frame type!\n");
        }else if ((*type_subtype & 12) == 0){  //type = 00 ->  management
		if ((*type_subtype & 240) == 128) is_beacon = 1; // 10000000 and 11110000 = 10000000 -> trata-se de um beacon
		struct mgmt_header_t *hdr = (struct mgmt_header_t *) (packet + rthdr->it_len);

		if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0){
			 printf("connection error\n");
		}else{
			printf("connected\n");
			char message[6];

			//message[0] = hdr->sa[0];
			//printf("%02x:%02x:%02x\n", message[0], message[1],message[2]);
			//struct device *new_dev = (struct device *) malloc (sizeof(struct device));
			//new_dev->address[0] = hdr->sa[0];
			//FILE *fd = fdopen(socket_desc, "w");
			sprintf(message,"%02x:%02x:%02x:%02x:%02x:%02x %s %d \n", hdr->sa[0],
                	                                                    hdr->sa[1],
                        	                                            hdr->sa[2],
                                	                                    hdr->sa[3],
                                        	                            hdr->sa[4],
                                                	                    hdr->sa[5],
									    hostname,
									    is_beacon);
			int sockerr = send(socket_desc, message, strlen(message) , 0);
			if (sockerr >= 0){

			 	printf("%s sended!\n", message);
			}else{
				printf("socket error %d -> %s\n", sockerr, message);
			}
		}

        }else if ((*type_subtype & 8) == 8){  //type = 10 -> data
		struct data_header_t *hdr = (struct data_header_t *) (packet + rthdr->it_len);
		/*if (devices == NULL){
			struct device *new_dev = (struct device *) malloc (sizeof(struct device));
			new_dev->address[0] = hdr->sa[0];
			new_dev->next = NULL;
			sniffed_devices++;
			devices = new_dev;
		}else{

			device *dev = devices;
			while (dev != NULL){
				for(int i=0;i<6;i++){
					if (hdr->sa[i] != dev->address[i]){
						if ((dev->next==NULL)){
							struct device *new_dev = (struct device *) malloc (sizeof(struct device));
							for (int i=0;i<6;i++){
        	        	        	        	new_dev->address[i] = hdr->sa[i];
	        	        	        	}

							new_dev->next = NULL;
							sniffed_devices++;
							new_dev->count = 1;
							dev->next = new_dev;
							dev = NULL;
							i = 6;
						}else{
							dev = dev->next;
							i=0;
						}
					}else if ((i == 5)){
						dev->count++;
						dev = NULL; //ja esta na lista
					}
				}
			}
		}*/

		if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0){
			 printf("connection error\n");
		}else{
			printf("connected\n");
			char message[6];

			//message[0] = hdr->sa[0];
			//printf("%02x:%02x:%02x\n", message[0], message[1],message[2]);
			//struct device *new_dev = (struct device *) malloc (sizeof(struct device));
			//new_dev->address[0] = hdr->sa[0];
			//FILE *fd = fdopen(socket_desc, "w");
			sprintf(message,"%02x:%02x:%02x:%02x:%02x:%02x %s %d \n", hdr->sa[0],
                	                                                    hdr->sa[1],
                        	                                            hdr->sa[2],
                                	                                    hdr->sa[3],
                                        	                            hdr->sa[4],
                        	                    			    hdr->sa[5],
									    hostname,
									    is_beacon);

			int sockerr = send(socket_desc, message, strlen(message) , 0);
			if (sockerr >= 0){

			 	printf("%s sended!\n", message);
			}else{
				printf("socket error %d -> %s\n", sockerr, message);
			}
		}


        }else if ((*type_subtype & 4) == 4){
                struct control_header_t *hdr = (struct control_header_t *) (packet + rthdr->it_len);
		//hdr = (struct control_header_t *) (packet + rthdr->it_len);
                //printf("controle!\n");
        }else{
                printf("Erro -> %d\n", *type_subtype);
                struct data_header_t *hdr = (struct data_header_t *) (packet + rthdr->it_len);

        }
	close(socket_desc);
	//sleep(0.5);
	//printf("Dispositivos encontrados: %d\r", sniffed_devices);

}
