#include "radiotap.h"
#include "ieee80211.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>



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


    if(handle==NULL){ 
        printf("ERRO: %s\n", errbuf);
    }

    if((linktype = pcap_datalink(handle)) < 0){
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return -1;
    }

    printf("Starting capture loop\n");
    pcap_loop(handle, 100, packetHandler, NULL);
    return 0;
}

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

/* struct radiotap_header{
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
            for (int i=0;i<6;i++){
                new_dev->address[i] = hdr->sa[i];
            }
            sniffed_devices++;
            new_dev->next = NULL;
//devices = new_dev;
            printf("First!");
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
                            dev->next = new_dev;
                            sniffed_devices++;
                            dev = NULL;
                        }else{
                            dev = dev->next;
                        }
                        i = 6;

                    }else if ((i == 5)){
                        dev = NULL;
                    }else{
                        dev = dev->next;
                    }
                }
            }
        }

                //printf("%d -> gerenciamento\n", *type_subtype);
    }else if ((*type_subtype & 8) == 8){
//printf("--------------------------\n");
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
            for (int i=0;i<6;i++){
                new_dev->address[i] = hdr->sa[i];
            }
            new_dev->next = NULL;
            sniffed_devices++;
//devices = new_dev;
            printf("First!");
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
                        dev->next = new_dev;
                        dev = NULL;
                    }else{
                        dev = dev->next;
                    }
                    i = 6;

                }else if ((i == 5)){
                    dev = NULL;
                }else{
                    dev = dev->next;
                }
            }   
        }
    }

//printf("%d -> dados\n", *type_subtype);
    }else if ((*type_subtype & 4) == 4){
            struct control_header_t *hdr = (struct control_header_t *) (packet + rthdr->it_len);
//hdr = (struct control_header_t *) (packet + rthdr->it_len);
        //printf("controle!\n");
    }else{
        printf("Erro -> %d\n", *type_subtype);
        struct data_header_t *hdr = (struct data_header_t *) (packet + rthdr->it_len);

    }

/*printf("Dispositivos encontrados: \n");
printf("%d     ", sniffed_devices);
printf("\r");*/
    if (sniffed_devices == 9999){
        device * aux = devices;
        while(aux)
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", aux->address[0],
                                                      aux->address[1],
                                                      aux->address[2],
                                                      aux->address[3],
                                                      aux->address[4],
                                                      aux->address[5]);
            aux = aux->next;
        }
    }
}
