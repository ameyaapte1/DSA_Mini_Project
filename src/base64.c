/*
 *	File Encryption using RSA : File encryption using RSA 
 *      Copyright (C) 2016  Ameya Apte
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "base64.h"

char *base64_encode (unsigned char *source, size_t len) {
  int i = 0,j=0;
  char *enc = NULL;
  size_t size = 0;
  unsigned char buffer[4], temp[3];

  enc = (char *) malloc(0);
  if (enc == NULL) { return NULL; }

  while (len--) {
    temp[i++] = *(source++);

    if (i == 3) {

      buffer[0] = (temp[0] & 0xfc) >> 2;
      buffer[1] = ((temp[0] & 0x03) << 4) + ((temp[1] & 0xf0) >> 4);
      buffer[2] = ((temp[1] & 0x0f) << 2) + ((temp[2] & 0xc0) >> 6);
      buffer[3] = temp[2] & 0x3f;

      enc = (char *) realloc(enc, size + 4);
      for (i = 0; i < 4; i++) {
        enc[size++] = base64_table[buffer[i]];
      }
      i = 0;
    }
  }

  if (i > 0) {
    for (j = i; j < 3; j++) {
      temp[j] = '\0';
    }

    buffer[0] = (temp[0] & 0xfc) >> 2;
    buffer[1] = ((temp[0] & 0x03) << 4) + ((temp[1] & 0xf0) >> 4);
    buffer[2] = ((temp[1] & 0x0f) << 2) + ((temp[2] & 0xc0) >> 6);
    buffer[3] = temp[2] & 0x3f;

    for (j = 0; (j < i + 1); j++) {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = base64_table[buffer[j]];
    }

    while ((i++ < 3)) {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = '=';
    }
  }

  enc[size] = '\0';

  return enc;
}

unsigned char *base64_decode (char *source, size_t len, size_t *output_len) {
  int i = 0, j = 0, l = 0;
  size_t size = 0;
  unsigned char *dec = NULL, buffer[3], temp[4];

  dec = (unsigned char *) malloc(0);
  if (dec == NULL) { return NULL; }

  while (len--) {
    if (source[j] == '=') { break; }
    if (!(isalnum(source[j]) || source[j] == '+' || source[j] == '/')) { break; }

    temp[i++] = source[j++];

    if (i == 4) {
      for (i = 0; i < 4; i++) {
        for (l = 0; l < 64; l++) {
          if (temp[i] == base64_table[l]) {
            temp[i] = l;
            break;
          }
        }
      }

      buffer[0] = (temp[0] << 2) + ((temp[1] & 0x30) >> 4);
      buffer[1] = ((temp[1] & 0xf) << 4) + ((temp[2] & 0x3c) >> 2);
      buffer[2] = ((temp[2] & 0x3) << 6) + temp[3];

      dec = (unsigned char *) realloc(dec, size + 3);
      for (i = 0; i < 3; i++) {
        dec[size++] = buffer[i];
      }

      i = 0;
    }
  }

  if (i > 0) {
    for (j = i; j < 4; j++) {
      temp[j] = '\0';
    }

    for (j = 0; j < 4; j++) {
        for (l = 0; l < 64; l++) {
          if (temp[j] == base64_table[l]) {
            temp[j] = l;
            break;
          }
        }
    }

    buffer[0] = (temp[0] << 2) + ((temp[1] & 0x30) >> 4);
    buffer[1] = ((temp[1] & 0xf) << 4) + ((temp[2] & 0x3c) >> 2);
    buffer[2] = ((temp[2] & 0x3) << 6) + temp[3];

    dec = (unsigned char *) realloc(dec, size + (i - 1));
    for (j = 0; (j < i - 1); j++) {
      dec[size++] = buffer[j];
    }
  }

  dec = (unsigned char *) realloc(dec, size + 1);
  dec[size] = '\0';

  *output_len = size;
  
  return dec;
}
