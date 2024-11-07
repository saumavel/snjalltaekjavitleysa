#include "crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <aes/esp_aes.h>
#include <esp_log.h>
#include <esp_random.h>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "lownet.h"
#include "serial_io.h"

static esp_aes_context aes_ctx;
static SemaphoreHandle_t aes_mutex;
static const char *TAG = "CRYPT";

// Static buffer for key storage
static uint8_t key_storage[LOWNET_KEY_SIZE_AES];
static lownet_key_t current_key = {.bytes = key_storage,
                                   .size = LOWNET_KEY_SIZE_AES};

void crypt_init() {
  // Initialize AES context and mutex
  esp_aes_init(&aes_ctx);
  aes_mutex = xSemaphoreCreateMutex();
}

void crypt_decrypt(const lownet_secure_frame_t *cipher,
                   lownet_secure_frame_t *plain) {
  const lownet_key_t *key = lownet_get_key();

  if (!key || !key->bytes || key->size != LOWNET_KEY_SIZE_AES) {
    ESP_LOGE(TAG, "Invalid key for decryption");
    return;
  }

  // Acquire the mutex to ensure exclusive access
  if (xSemaphoreTake(aes_mutex, portMAX_DELAY) == pdTRUE) {
    // Copy unencrypted header and IVT
    memcpy(plain, cipher, LOWNET_UNENCRYPTED_SIZE);
    memcpy(plain->ivt, cipher->ivt, LOWNET_IVT_SIZE);

    // Initialize AES context
    if (esp_aes_setkey(&aes_ctx, key->bytes, 256) != 0) {
      ESP_LOGE(TAG, "Failed to set AES key");
      xSemaphoreGive(aes_mutex); // Release mutex before returning
      return;
    }

    // Decrypt payload using CBC mode
    uint8_t iv[LOWNET_IVT_SIZE];
    memcpy(iv, cipher->ivt, LOWNET_IVT_SIZE);

    if (esp_aes_crypt_cbc(&aes_ctx, ESP_AES_DECRYPT, LOWNET_ENCRYPTED_SIZE, iv,
                          (uint8_t *)&cipher->protocol,
                          (uint8_t *)&plain->protocol) != 0) {
      ESP_LOGE(TAG, "Decryption failed");
      xSemaphoreGive(aes_mutex); // Release mutex before returning
      return;
    }

    // Release the mutex
    xSemaphoreGive(aes_mutex);
  } else {
    ESP_LOGE(TAG, "Failed to acquire mutex for decryption");
  }
}

void crypt_encrypt(const lownet_secure_frame_t *plain,
                   lownet_secure_frame_t *cipher) {
  const lownet_key_t *key = lownet_get_key();
  if (!key || !key->bytes || key->size != LOWNET_KEY_SIZE_AES) {
    ESP_LOGE(TAG, "Invalid key for encryption");
    return;
  }

  // Acquire the mutex to ensure exclusive access
  if (xSemaphoreTake(aes_mutex, portMAX_DELAY) == pdTRUE) {
    // Copy unencrypted header
    memcpy(cipher, plain, LOWNET_UNENCRYPTED_SIZE);
    memcpy(cipher->ivt, plain->ivt, LOWNET_IVT_SIZE);

    // Initialize AES context
    if (esp_aes_setkey(&aes_ctx, key->bytes, 256) != 0) {
      ESP_LOGE(TAG, "Failed to set AES key");
      xSemaphoreGive(aes_mutex); // Release mutex before returning
      return;
    }

    // Encrypt payload using CBC mode
    uint8_t iv[LOWNET_IVT_SIZE];
    memcpy(iv, cipher->ivt, LOWNET_IVT_SIZE);

    if (esp_aes_crypt_cbc(&aes_ctx, ESP_AES_ENCRYPT, LOWNET_ENCRYPTED_SIZE, iv,
                          (uint8_t *)&plain->protocol,
                          (uint8_t *)&cipher->protocol) != 0) {
      ESP_LOGE(TAG, "Encryption failed");
      xSemaphoreGive(aes_mutex); // Release mutex before returning
      return;
    }

    // Release the mutex
    xSemaphoreGive(aes_mutex);
  } else {
    ESP_LOGE(TAG, "Failed to acquire mutex for encryption");
  }
}

// Usage: crypt_command(KEY)
// Pre:   KEY is a valid AES key or NULL
// Post:  If key == NULL encryption has been disabled
//        Else KEY has been set as the encryption key to use for
//        lownet communication.
void crypt_setkey_command(char *args) {
  if (!args || strlen(args) == 0) {
    // Disable encryption if no key provided
    lownet_set_key(NULL);
    serial_write_line("Encryption disabled");
    return;
  }

  // Remove whitespace
  while (*args == ' ')
    args++;

  // Check for predefined keys
  if (strcmp(args, "0") == 0) {
    lownet_set_stored_key(0);
    serial_write_line("Using base_shared_key");
    return;
  }

  if (strcmp(args, "1") == 0) {
    lownet_set_stored_key(1);
    serial_write_line("Using alt_shared_key");
    return;
  }

  // For custom key, convert string to key bytes
  memset(key_storage, 0, LOWNET_KEY_SIZE_AES); // Zero the storage

  // Convert ASCII ACDC2023 to bytes
  for (size_t i = 0; i < strlen(args) && i < LOWNET_KEY_SIZE_AES; i++) {
    key_storage[i] = args[i];
  }

  current_key.bytes = key_storage;
  current_key.size = LOWNET_KEY_SIZE_AES;
  // Set the new key
  lownet_set_key(&current_key);
  serial_write_line("Encryption key set");
}

void crypt_test_command(char *str) {
  if (!str) {
    serial_write_line("Error: You gotta input the string baby!");
    return;
  }
  if (!lownet_get_key()) {
    serial_write_line("No encryption key set!");
    return;
  }
  // Check if str length exceeds the payload limit
  if (strlen(str) >= sizeof(((lownet_secure_frame_t *)0)->payload)) {
    ESP_LOGE(TAG, "Input string too large for payload");
    serial_write_line("Error: Input string too large for payload");
    return;
  }

  // Encrypts and then decrypts a string, can be used to sanity check your
  // implementation.
  lownet_secure_frame_t plain;
  lownet_secure_frame_t cipher;
  lownet_secure_frame_t back;

  memset(&plain, 0, sizeof(lownet_secure_frame_t));
  memset(&cipher, 0, sizeof(lownet_secure_frame_t));
  memset(&back, 0, sizeof(lownet_secure_frame_t));

  const uint8_t cipher_magic[2] = {0x20, 0x4e};

  memcpy(plain.magic, cipher_magic, sizeof cipher_magic);
  plain.source = lownet_get_device_id();
  plain.destination = 0xFF;
  plain.protocol = LOWNET_PROTOCOL_CHAT;
  plain.length = strlen(str);

  // *((uint32_t*) plain.ivt) = 123456789; // removed in order to use random IVT
  strcpy((char *)plain.payload, str);

  crypt_encrypt(&plain, &cipher);

  if (memcmp(&plain, &cipher, LOWNET_UNENCRYPTED_SIZE) != 0) {
    serial_write_line("Unencrypted part of frame not preserved!");
    return;
  }
  if (memcmp(&plain.ivt, &cipher.ivt, LOWNET_IVT_SIZE) != 0) {
    serial_write_line("IVT not preserved!");
    return;
  }

  crypt_decrypt(&cipher, &back);

  if (memcmp(&plain, &back, sizeof plain) == 0) {
    serial_write_line("Encrypt/Decrypt successful");
    return;
  }

  serial_write_line("Encrypt/Decrypt failed");

  char msg[200];
  snprintf(msg, sizeof msg,
           "Unencrypted content: %s\n"
           "IVT:                 %s\n"
           "Encrypted content:   %s\n",
           memcmp(&plain, &back, LOWNET_UNENCRYPTED_SIZE) == 0 ? "Same"
                                                               : "Different",
           memcmp(&plain.ivt, &back.ivt, LOWNET_IVT_SIZE) == 0 ? "Same"
                                                               : "Different",
           memcmp(&plain.protocol, &back.protocol, LOWNET_ENCRYPTED_SIZE) == 0
               ? "Same"
               : "Different");

  serial_write_line(msg);
}
