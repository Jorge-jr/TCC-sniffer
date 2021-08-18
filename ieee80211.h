#include <stdint.h>

struct mgmt_header_t {
    //uint16_t   fc;
    uint8_t type_subtype;
    uint8_t fc;
    uint16_t   duration;
    uint8_t    da[6];
    uint8_t    sa[6];
    uint8_t    bssid[6];
    uint16_t   seq_ctrl;
};

struct data_header_t {
	uint8_t type_subtype;
	uint8_t order_flag;
	uint16_t duration;
	uint8_t STA_address[6];
	uint8_t bssid[6];
	uint8_t sa[6];
};

struct control_header_t {
        uint8_t type_subtype;
        uint8_t order_flag;
        uint16_t duration;
};
