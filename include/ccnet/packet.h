/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_PEER_MSG
#define CCNET_PEER_MSG

#define CCNET_MSG_OK         0
#define CCNET_MSG_HANDSHAKE  1
#define CCNET_MSG_REQUEST    2
#define CCNET_MSG_RESPONSE   3
#define CCNET_MSG_UPDATE     4
#define CCNET_MSG_RELAY      5  /* NOT USED NOW */
#define CCNET_MSG_ENCPACKET  6  /* an encrypt packet */

typedef struct ccnet_header    ccnet_header;

struct ccnet_header {
    uint8_t  version;
    uint8_t  type;
    uint16_t length;            /* length of payload */
    uint32_t id;                /* used as length in ecrypted packet */
};

typedef struct ccnet_packet    ccnet_packet;

struct ccnet_packet {
    struct ccnet_header header;
    char data[0];
};

#define CCNET_PACKET_MAX_PAYLOAD_LEN 65535
#define CCNET_PACKET_LENGTH_HEADER       8
#define CCNET_USER_ID_START           1000

#endif
