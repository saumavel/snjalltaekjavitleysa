// CSTDLIB includes.
#include <freertos/FreeRTOS.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <esp_log.h>
#include <esp_random.h>

#include "esp_task_wdt.h"

// LowNet includes.
#include "lownet.h"

#include "cli.h"
#include "crypt.h"
#include "serial_io.h"
#include "utility.h"

#include "chat.h"
#include "cli.h"
#include "command.c"
#include "ping.h"

// Usage: help_command(NULL)
// Pre:   None, this command takes no arguments.
// Post:  A list of available commands has been written to the serial port.
void help_command(char *);

void crypt_init(void);

const command_t commands[] = {
    {"shout", "/shout MSG                   Broadcast a message.",
     shout_command},
    {"tell", "/tell ID MSG or @ID MSG      Send a message to a specific node",
     tell_command},
    {"ping", "/ping ID                     Check if a node is online",
     ping_command},
    {"date", "/date                        Print the current time",
     date_command},
    {"setkey",
     "/setkey [KEY|0|1]            Set the encryption key to use.  If no key "
     "is provided encryption is disabled",
     crypt_setkey_command},
    {"id", "/id                          Print your ID", id_command},
    {"testenc",
     "/testenc [STR]               Run STR through a encrypt/decrypt cycle to "
     "verify that encryption works",
     crypt_test_command},
    {"help", "/help                        Print this help", help_command}};

const size_t NUM_COMMANDS = sizeof commands / sizeof(command_t);
#define FIND_COMMAND(_command) (find_command(_command, commands, NUM_COMMANDS))

// Usage: help_command(NULL)
// Pre:   None, this command takes no arguments.
// Post:  A list of available commands has been written to the serial port.
void help_command(char *) {
  /*
          Loop Invariant:
          0 <= i < NUM_COMMANDS
          forall x | 0 <= x < i : commands[x] has been written to the serial
     port
   */
  for (size_t i = 0; i < NUM_COMMANDS; ++i)
    serial_write_line(commands[i].description);
  serial_write_line("Any input not preceded by a '/' or '@' will be treated as "
                    "a broadcast message.");
}

void app_frame_dispatch(const lownet_frame_t *frame) {
  // Mask the signing bits.
  switch (frame->protocol & 0b00111111) {
  case LOWNET_PROTOCOL_TIME:
    // Ignore TIME packets, deprecated.
    break;

  case LOWNET_PROTOCOL_CHAT:
    chat_receive(frame);
    break;

  case LOWNET_PROTOCOL_PING:
    ping_receive(frame);
    break;

  case LOWNET_PROTOCOL_COMMAND:
    command_receive(frame);
    break;
  }
}

void app_main(void) {
  char msg_in[MSG_BUFFER_LENGTH];
  char msg_out[MSG_BUFFER_LENGTH];

  // Configure the task watchdog timer if it hasn’t been initialized yet
  /*if (esp_task_wdt_status(NULL) ==*/
  /*    ESP_ERR_NOT_FOUND) { // Check if TWDT is initialized*/
  /*  esp_task_wdt_config_t wdt_config = {*/
  /*      .timeout_ms = 10000,  // 10 seconds*/
  /*      .trigger_panic = true // Enable panic on watchdog timeout*/
  /*  };*/
  /*  if (esp_task_wdt_init(&wdt_config) != ESP_OK) {*/
  /*    ESP_LOGE("WDT_INIT", "Failed to initialize Task Watchdog Timer");*/
  /*  }*/
  /*  esp_task_wdt_add(NULL); // Add the main task to the watchdog*/
  /*} else {*/
  /*  ESP_LOGI("WDT_INIT", "Task Watchdog Timer already initialized, skipping");*/
  /*}*/

  // Initialize the cryptographic module
  crypt_init(); // Call to initialize the AES context and mutex

  // Initialize the serial services.
  init_serial_service();

  // Initialize the LowNet services.
  lownet_init(app_frame_dispatch, crypt_encrypt, crypt_decrypt);

  // Initialize the command module
  /*command_init();*/

  // Dummy implementation -- this isn't true network time!  Following 2
  //	lines are not needed when an actual source of network time is present.
  lownet_time_t init_time = {1, 0};
  lownet_set_time(&init_time);

  /*TickType_t lastCheckTime = xTaskGetTickCount();*/

  while (true) {
    memset(msg_in, 0, MSG_BUFFER_LENGTH);
    memset(msg_out, 0, MSG_BUFFER_LENGTH);

    if (!serial_read_line(msg_in)) {
      // Quick & dirty input parse.
      if (msg_in[0] == 0)
        continue;
      if (msg_in[0] == '/') {
        char *name = strtok(msg_in + 1, " ");
        command_fun_t command = FIND_COMMAND(name);
        if (!command) {
          char buffer[17 + strlen(name) + 1];
          sprintf(buffer, "Invalid command: %s", name);
          serial_write_line(buffer);
          continue;
        }
        char *args = strtok(NULL, "\n");
        command(args);
      } else if (msg_in[0] == '@') {
        FIND_COMMAND("tell")(msg_in + 1);
      } else {
        // Default, chat broadcast message.
        FIND_COMMAND("shout")(msg_in);
      }
    }
    // Reset the watchdog more frequently
    /*esp_task_wdt_reset();*/
    /**/
    /*// Periodically check memory every 5 seconds*/
    /*if (xTaskGetTickCount() - lastCheckTime > pdMS_TO_TICKS(5000)) {*/
    /*  lastCheckTime = xTaskGetTickCount();*/
    /*  size_t freeHeap = esp_get_free_heap_size();*/
    /*  ESP_LOGI("MEMORY_CHECK", "Free heap size: %u bytes", freeHeap);*/
    /*}*/
    /**/
    /*vTaskDelay(pdMS_TO_TICKS(100)); // Delay to prevent busy-waiting*/
  }
}
