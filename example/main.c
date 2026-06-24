/**
 * @file main.c
 * @author Daan Pape <daan@dptechnics.com>
 * @brief This example shows how to connect a linux application to the BlueCherry platform.
 * @version 1.0.0
 * @date 2026-06-24
 * @copyright Copyright (c) 2025 DPTechnics BV
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#include <bluecherry/bclite.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define CERT_FILE "device.crt"
#define KEY_FILE  "device.key"

static char cert_buf[BLUECHERRY_ZTP_CERT_BUF_SIZE];
static char key_buf[BLUECHERRY_ZTP_PKEY_BUF_SIZE];

/**
 * @brief Read or write a certificate/key file for ZTP provisioning.
 *
 * On read (read=true) the file is loaded into a static buffer and a pointer to
 * that buffer is returned, or NULL if the file does not exist. On write
 * (read=false) the PEM string in args is persisted to disk.
 *
 * @param read  true to read the file, false to write it.
 * @param secure true for the private key file, false for the certificate file.
 * @param args  On write: const char* PEM string to persist. Unused on read.
 *
 * @return On read: pointer to the file contents, or NULL if not found.
 *         On write: always NULL.
 */
static const char* ztp_bio_handler(bool read, bool secure, void* args)
{
  const char* filename = secure ? KEY_FILE : CERT_FILE;
  char* buf = secure ? key_buf : cert_buf;
  size_t buf_size = secure ? BLUECHERRY_ZTP_PKEY_BUF_SIZE : BLUECHERRY_ZTP_CERT_BUF_SIZE;

  if(read) {
    FILE* f = fopen(filename, "r");
    if(!f) {
      return NULL;
    }
    size_t n = fread(buf, 1, buf_size - 1, f);
    fclose(f);
    if(n == 0) {
      return NULL;
    }
    buf[n] = '\0';
    return buf;
  } else {
    const char* data = (const char*)args;
    FILE* f = fopen(filename, "w");
    if(!f) {
      fprintf(stderr, "Failed to write %s\n", filename);
      return NULL;
    }
    fputs(data, f);
    fclose(f);
    return NULL;
  }
}

/**
 * @brief Handle an incoming MQTT message from the BlueCherry cloud.
 *
 * @param topic The topic index of the received message.
 * @param len   The payload length in bytes.
 * @param data  The payload bytes.
 * @param args  Unused user pointer.
 */
static void msg_handler(uint8_t topic, uint16_t len, const uint8_t* data, void* args)
{
  (void)args;
  printf("Received message on topic 0x%02X (%u bytes): %.*s\n", topic, len, (int)len,
         (const char*)data);
}

/**
 * @brief Return the current CPU usage as a percentage.
 *
 * Computes the delta between two consecutive reads of /proc/stat to derive
 * usage over the last interval.
 *
 * @return CPU usage in percent [0, 100], or -1.0f on error.
 */
static float get_cpu_usage(void)
{
  static unsigned long long prev_total = 0;
  static unsigned long long prev_idle = 0;

  FILE* f = fopen("/proc/stat", "r");
  if(!f) {
    return -1.0f;
  }

  unsigned long long user, nice, system, idle, iowait, irq, softirq;
  int matched =
      fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle, &iowait,
             &irq, &softirq);
  fclose(f);

  if(matched != 7) {
    return -1.0f;
  }

  unsigned long long total = user + nice + system + idle + iowait + irq + softirq;
  unsigned long long total_diff = total - prev_total;
  unsigned long long idle_diff = idle - prev_idle;

  prev_total = total;
  prev_idle = idle;

  if(total_diff == 0) {
    return 0.0f;
  }

  return 100.0f * (1.0f - (float)idle_diff / (float)total_diff);
}

/**
 * @brief Return the amount of available RAM in megabytes.
 *
 * Reads MemAvailable from /proc/meminfo.
 *
 * @return Available RAM in MB, or 0 on error.
 */
static unsigned long get_available_ram_mb(void)
{
  FILE* f = fopen("/proc/meminfo", "r");
  if(!f) {
    return 0;
  }

  char line[128];
  unsigned long mem_available_kb = 0;
  while(fgets(line, sizeof(line), f)) {
    if(sscanf(line, "MemAvailable: %lu kB", &mem_available_kb) == 1) {
      break;
    }
  }
  fclose(f);

  return mem_available_kb / 1024;
}

/**
 * @brief The entrypoint of the BlueCherry lite demo application.
 *
 * This application will perform ZTP when the device is not yet registered.
 * Certificates will be stored in the directory where the application runs. If
 * the device manages to connect the application will send CPU usage and RAM
 * usage to topic 0x84 every 5 seconds.
 *
 * Usage: bluecherry-example <device-type-id>
 *   device-type-id  8-character BlueCherry device type identifier
 *
 * @param argc The number of arguments passed to the program.
 * @param argv The array of arguments passed to the program.
 *
 * @return 0 on success.
 */
int main(int argc, char* argv[])
{
  if(argc < 2 || strlen(argv[1]) != BLUECHERRY_ZTP_ID_LEN) {
    fprintf(stderr, "Usage: %s <device-type-id>\n", argv[0]);
    fprintf(stderr, "  device-type-id  exactly %d characters (e.g. demo0001)\n",
            BLUECHERRY_ZTP_ID_LEN);
    return 1;
  }

  const char* device_type = argv[1];

  printf("Initializing BlueCherry (device type: %s)...\n", device_type);

  if(!bluecherry_init_ztp(ztp_bio_handler, NULL, device_type, msg_handler, NULL, true)) {
    fprintf(stderr, "Failed to initialize BlueCherry\n");
    return 1;
  }

  printf("BlueCherry initialized. Sending telemetry every 5 seconds.\n");

  /* Prime the CPU measurement so the first reported value is meaningful. */
  get_cpu_usage();

  while(1) {
    struct timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
    nanosleep(&ts, NULL);

    float cpu = get_cpu_usage();
    unsigned long ram_mb = get_available_ram_mb();

    char payload[64];
    int payload_len = snprintf(payload, sizeof(payload), "cpu=%.1f%%,ram=%luMB", cpu, ram_mb);
    if(payload_len > 0) {
      bluecherry_publish(0x84, (uint16_t)payload_len, (const uint8_t*)payload);
      printf("Published: %s\n", payload);
    }
  }

  return 0;
}
