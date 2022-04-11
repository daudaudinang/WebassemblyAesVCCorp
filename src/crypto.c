#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include "lib/aes.c"

// #include <emscripten/emscripten.h>

#define CBC 1
#define AES256 1
#define AES128 0


// Nếu chỉ muốn đổi key và iv chỉ cần đổi ở đây rồi build lại, không cần đọc code bên dưới
const uint8_t key[] = "acd205251ea9a0abfccecc2bee378a63";
const uint8_t iv[] = "acd205251ea9a0ab";

char *bin2hex(unsigned char *p, int len)
{
    char *hex = malloc(((2*len) + 1));
    char *r = hex;

    while(len && p)
    {
        (*r) = ((*p) & 0xF0) >> 4;
        (*r) = ((*r) <= 9 ? '0' + (*r) : 'A' - 10 + (*r));
        r++;
        (*r) = ((*p) & 0x0F);
        (*r) = ((*r) <= 9 ? '0' + (*r) : 'A' - 10 + (*r));
        r++;
        p++;
        len--;
    }
    *r = '\0';
    return hex;
}

int pkcs7_padding_pad_buffer( uint8_t *buffer,  size_t data_length, size_t buffer_size, uint8_t modulus ){
  uint8_t pad_byte = modulus - ( data_length % modulus ) ;
  if( data_length + pad_byte > buffer_size ){
    return -pad_byte;
  }
  int i = 0;
  while( i <  pad_byte){
    buffer[data_length+i] = pad_byte;
    i++;
  }
  return pad_byte;
}

int pkcs7_padding_valid( uint8_t *buffer, size_t data_length, size_t buffer_size, uint8_t modulus ){
  uint8_t expected_pad_byte = modulus - ( data_length % modulus ) ;
  if( data_length + expected_pad_byte > buffer_size ){
    return 0;
  }
  int i = 0;
  while( i < expected_pad_byte ){
    if( buffer[data_length + i] != expected_pad_byte){
      return 0;
    }
    i++;
  }
  return 1;
}

size_t pkcs7_padding_data_length( uint8_t * buffer, size_t buffer_size, uint8_t modulus ){
  /* test for valid buffer size */
  if( buffer_size % modulus != 0 ||
    buffer_size < modulus ){
    return 0;
  }
  uint8_t padding_value;
  padding_value = buffer[buffer_size-1];
  /* test for valid padding value */
  if( padding_value < 1 || padding_value > modulus ){
    return buffer_size;
  }
  /* buffer must be at least padding_value + 1 in size */
  if( buffer_size < padding_value + 1 ){
    return 0;
  }
  uint8_t count = 1;
  buffer_size --;
  for( ; count  < padding_value ; count++){
    buffer_size --;
    if( buffer[buffer_size] != padding_value ){
      return 0;
    }
  }
  return buffer_size;
}

char* encryptAES_CBC(char* message){
    // Kiểm tra chuỗi, thêm padding nếu message k phải bội số của 16 (Do thằng tiny-aes không có chức năng thêm padding nên ta cần dùng pkcs7_padding)
    int oldLen = strlen(message);
    int newLen = oldLen;
    if(oldLen % 16){
        newLen += 16 - (oldLen % 16);
    }

    uint8_t str[newLen];

    memset(str, 0, newLen);

    // Fill full data từ message vào mảng mới đã
    for(int i = 0; i < oldLen; i++){
        str[i] = (uint8_t) message[i];
    }

    int messagePad = pkcs7_padding_pad_buffer(str, oldLen, sizeof(str), 16);

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, str, newLen);

    // Chuyển data từ bin sang hex
    char *encryptedMessage = bin2hex(str, sizeof str);
    return encryptedMessage;
}

char* decryptAES_CBC(char* message){
  uint8_t str[strlen(message)/2];
  memset(str, 0, strlen(message)/2);

  for (int i = 0; i < sizeof(str); i++) {
    sscanf(message + 2*i, "%2hhx", &str[i]);
  }

  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_decrypt_buffer(&ctx, str, sizeof(str));

  // Sau khi giải mã xong ta cần bỏ đi phần padding đã thêm vào trước khi encrypt để đưa ra được kết quả chính xác như ban đầu
  size_t actualDataLength = pkcs7_padding_data_length(str, sizeof(str), 16);

  // Tạo 1 array tạm để lưu giá trị của chuỗi sau khi đã cắt đi phần padding
  uint8_t tempMessage[actualDataLength + 1];    
  memset(tempMessage, 0, actualDataLength);

  // Nhớ thêm '\0' vào cuối array để nó xác định điểm kết thúc của array, tránh trường hợp chuyển sang char* bị lỗi
  tempMessage[actualDataLength] = '\0';

  for(int i = 0; i < actualDataLength; i++){
      tempMessage[i] = str[i];
  }

  char* decryptedMessage = (char*) tempMessage;
  return decryptedMessage;
}