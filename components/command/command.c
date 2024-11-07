#include "command.h"
#include <esp_log.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <string.h>

typedef enum { LISTENING, WAIT_SIG, WAIT_SIG1, WAIT_SIG2, READY } state_t;

typedef enum {
  SIGNED = 0b01,
  UNSIGNED = 0b00,
  SIG1 = 0b10,
  SIG2 = 0b11
} frame_type_t;

uint64_t sequence;
lownet_frame_t buffer[3];
state_t state;
uint8_t key_hash[CMD_HASH_SIZE];
uint8_t msg_hash[CMD_HASH_SIZE];
mbedtls_pk_context ctx;

frame_type_t get_frame_type(const lownet_frame_t *frame) {
  uint8_t msb_bits = (frame->protocol >> 6) & 0b11;
  return (frame_type_t)msb_bits;
}

void command_init() {
  /*sequence = 0;*/
  /*state = LISTENING;*/
  /*memset(buffer, 0, sizeof(buffer));*/
  /**/
  /*const char *pem = lownet_get_signing_key();*/
  /*if (pem) {*/
  /*  mbedtls_sha256((const unsigned char *)pem, strlen(pem), key_hash, 0);*/
  /*} else {*/
  /*  ESP_LOGE("COMMAND", "Failed to retrieve signing key");*/
  /*}*/
  /**/
  /*// Initialize the public key context and parse the public key*/
  /*mbedtls_pk_init(&ctx);*/
  /*if (pem && mbedtls_pk_parse_public_key(&ctx, (const unsigned char *)pem,*/
  /*                                       strlen(pem) + 1) != 0) {*/
  /*  ESP_LOGE("COMMAND", "Failed to parse public key");*/
  /*}*/
  /*/*mbedtls_sha256((const unsigned char *)pem, strlen(pem), key_hash, 0);*/
  /**/
  /*/*mbedtls_pk_init(&ctx);*/
  /*/*mbedtls_pk_parse_public_key(&ctx, (const unsigned char *)pem,*/
  /*/*strlen(pem) + 1);*/
}

void command_receive(const lownet_frame_t *frame) {
  /*static uint8_t expected[CMD_BLOCK_SIZE];*/
  /*static uint8_t actual[CMD_BLOCK_SIZE];*/
  /*static uint8_t signature[CMD_BLOCK_SIZE];*/
  /**/
  /*frame_type_t type = get_frame_type(frame);*/
  /**/
  /*switch (type) {*/
  /*case UNSIGNED:*/
  /*  return;*/
  /*case SIGNED:*/
  /*  memcpy(&buffer[0], frame, sizeof(lownet_frame_t));*/
  /*  mbedtls_sha256((const unsigned char *)frame, sizeof(lownet_frame_t),*/
  /*                 msg_hash, 0);*/
  /*  state = WAIT_SIG;*/
  /*  break;*/
  /*case SIG1:*/
  /*  if (state != WAIT_SIG && state != WAIT_SIG1)*/
  /*    return;*/
  /*  const cmd_signature_t *sig1 = (const cmd_signature_t *)&frame->payload;*/
  /*  if (memcmp(msg_hash, sig1->hash_msg, CMD_HASH_SIZE) != 0)*/
  /*    return;*/
  /*  if (memcmp(key_hash, sig1->hash_key, CMD_HASH_SIZE) != 0)*/
  /*    return;*/
  /*  memcpy(&buffer[1], frame, sizeof(lownet_frame_t));*/
  /*  state = (state == WAIT_SIG) ? WAIT_SIG2 : READY;*/
  /*  break;*/
  /*case SIG2:*/
  /*  if (state != WAIT_SIG && state != WAIT_SIG2)*/
  /*    return;*/
  /*  const cmd_signature_t *sig2 = (const cmd_signature_t *)&frame->payload;*/
  /*  if (memcmp(msg_hash, sig2->hash_msg, CMD_HASH_SIZE) != 0)*/
  /*    return;*/
  /*  if (memcmp(key_hash, sig2->hash_key, CMD_HASH_SIZE) != 0)*/
  /*    return;*/
  /*  memcpy(&buffer[2], frame, sizeof(lownet_frame_t));*/
  /*  state = (state == WAIT_SIG) ? WAIT_SIG1 : READY;*/
  /*  break;*/
  /*}*/
  /**/
  /*if (state != READY)*/
  /*  return;*/
  /**/
  /*memset(expected, 0, 220);*/
  /*memset(expected + 220, 1, 4);*/
  /*memcpy(expected + 224, msg_hash, CMD_HASH_SIZE);*/
  /**/
  /*memcpy(signature, ((cmd_signature_t *)buffer[2].payload)->sig_part,*/
  /*       CMD_BLOCK_SIZE / 2);*/
  /**/
  /*mbedtls_rsa_public(mbedtls_pk_rsa(ctx), signature, actual);*/
  /**/
  /*if (memcmp(expected, actual, CMD_BLOCK_SIZE) != 0) {*/
  /*  memset(buffer, 0, sizeof buffer);*/
  /*  state = LISTENING;*/
  /*  return;*/
  /*}*/
  /**/
  /*cmd_packet_t *command = (cmd_packet_t *)buffer[0].payload;*/
  /**/
  /*// Process command*/
  /*memset(command, 0, sizeof *command);*/
  /*state = LISTENING;*/
}
