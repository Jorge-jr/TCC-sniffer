#include "radiotap.h"
#include "ieee80211.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <unistd.h>
//#include <signal.h>
#include <sys/socket.h>
//#include <netinet/ip.h>
//#include <netinet/tcp.h>
//#include <netinet/udp.h>
//#include <netinet/ip_icmp.h>



void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

typedef struct device{
	uint8_t address[6];
	struct device *next;
}device ;


device *devices;
int sniffed_devices = 0;

int main(int argc, char ** argv){

	char device[] = "mon0";
	char *errbuf;
	int linktype;

	printf("Monitorando a partir da interface: %s\n", device);

	pcap_t *handle;
	handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf);  //3000 ms buffer timeout


	if(handle==NULL){ printf("ERRO: %s\n", errbuf); }

	if((linktype = pcap_datalink(handle)) < 0){
		printf("pcap_datalink(): %s\n", pcap_geterr(handle));
		return -1;
	}

	printf("Starting capture loop\n");
	pcap_loop(handle, 1000, packetHandler, NULL);


	printf("\n");
	while(devices!=NULL){
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", devices->address[0],
                	                                  devices->address[1],
                        	                          devices->address[2],
                                	                  devices->address[3],
                                        	          devices->address[4],
                                                	  devices->address[5]);
		devices = devices->next;
	}

	return 0;


}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

/*	struct radiotap_header{
		uint8_t it_rev;
		uint8_t it_pad;
		uint16_t it_len;
	};*/

	struct ieee80211_radiotap_header *rthdr;
	rthdr = (struct ieee80211_radiotap_header *) packet;
	uint8_t *type_subtype = (uint8_t *) packet + rthdr->it_len;

        if ((*type_subtype & 12) == 12){
                printf("Not an ieee802.11 frame type!\n");
        }else if ((*type_subtype & 12) == 0){
//		printf("%d -> gerenciamento\n", *type_subtype);
		//printf("--------------------------\n");
		struct mgmt_header_t *hdr = (struct mgmt_header_t *) (packet + rthdr->it_len);
        	/*printf("%02x:%02x:%02x:%02x:%02x:%02x\n", hdr->sa[0],
                        			  	  hdr->sa[1],
                        			  	  hdr->sa[2],
                        			  	  hdr->sa[3],
                        			  	  hdr->sa[4],
                        			  	  hdr->sa[5]);*/

		//hdr = (struct mgmt_header_t *) (packet + rthdr->it_len);

		if (devices == NULL){
			struct device *new_dev = (struct device *) malloc (sizeof(struct device));
			/*for (int i=0;i<6;i++){
                                new_dev->address[i] = hdr->sa[i];
                        }*/

			new_dev->address[0] = hdr->sa[0];
			sniffed_devices++;
			new_dev->next = NULL;

			//printf("First coming...\n");
			devices = new_dev;
			//printf("First!\n");
		}else{
			//printf("Seg fault? 1 \n");
			device *dev = devices;
			while (dev != NULL){
				for(int i=0;i<6;i++){
					//printf("Seg fault? 2 \n");
					if (hdr->sa[i] != dev->address[i]){
						if ((dev->next==NULL)){
							struct device *new_dev = (struct device *) malloc (sizeof(struct device));
							for (int i=0;i<6;i++){
				                                new_dev->address[i] = hdr->sa[i];
                        				}
							//printf("Seg fault? 3 \n");
						/*	new_dev->address[0] = hdr->sa[0];
							new_dev->address[0] = hdr->sa[0];
							new_dev->address[0] = hdr->sa[0];
							new_dev->address[0] = hdr->sa[0];
							new_dev->address[0] = hdr->sa[0];
							new_dev->address[5] = hdr->sa[0];*/


							new_dev->next = NULL;
							dev->next = new_dev;
							sniffed_devices++;
							dev = NULL;
							i = 6;
						}else{
							//printf("Seg fault? 7\n");
							dev = dev->next;
							i = 0;
						}
						//i = 6;

					}else if ((i == 5)){
						//printf("Seg fault? 8 \n");
						dev = NULL;
					}/*else{
						printf("Seg Fault? 9 \n");
						dev = dev->next;
					}*/
				}
			}
		}


        }else if ((*type_subtype & 8) == 8){
		//printf("--------------------------\n");
//		printf("%d -> dados\n", *type_subtype);
		struct data_header_t *hdr = (struct data_header_t *) (packet + rthdr->it_len);
		/*printf("%02x:%02x:%02x:%02x:%02x:%02x\n", hdr->sa[0],
                                                          hdr->sa[1],
                                                          hdr->sa[2],
                                                          hdr->sa[3],
                                                          hdr->sa[4],
                                                          hdr->sa[5]);*/
		//hdr = (struct data_header_t *) (packet + rthdr->it_len);
		if (devices == NULL){
			struct device *new_dev = (struct device *) malloc (sizeof(struct device));
			/*for (int i=0;i<6;i++){
				new_dev->address[i] = hdr->sa[i];
			}*/
			new_dev->address[0] = hdr->sa[0];
			new_dev->next = NULL;
			sniffed_devices++;
			devices = new_dev;
			//printf("First!\n");
		}else{

			device *dev = devices;
			while (dev != NULL){
				for(int i=0;i<6;i++){
					//printf("dados -> entrando no for _ i=%d\n", i);
					if (hdr->sa[i] != dev->address[i]){
						//printf("entrando no 1 if - dados \n");
						if ((dev->next==NULL)){
							//printf("Entrando no if 2 dados (enderecos diferentes e o prox e NULL)\n");
							struct device *new_dev = (struct device *) malloc (sizeof(struct device));
							for (int i=0;i<6;i++){
        	        	        	        	new_dev->address[i] = hdr->sa[i];
	        	        	        	}
							//new_dev->address[0] = hdr->sa[0];

							new_dev->next = NULL;
							sniffed_devices++;
							dev->next = new_dev;
							dev = NULL;
							i = 6;
							//printf("Saiu do if 2\n");
						}else{
							//printf("Entrou no else 2 dados (enderecos diferentes prox !=NULL)\n");
							dev = dev->next;
							i=0;
							//printf("Saiu do else 2 \n");
						}
						//i = 6;
						//printf("Saindo do if 1\n");
					}else if ((i == 5)){
						//printf("Entrando no else if 1 i==5 (o endereco encontrado...saindo do while)\n");
						dev = NULL; //ja esta na lista
						//printf("Saindo do else if 1 \n");
					}
					//printf("Seg fault? 6 \n");
					//dev = dev->next;
				//printf("Final do for \n");
				}
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

	printf("Dispositivos encontrados: %d\r", sniffed_devices);

}
