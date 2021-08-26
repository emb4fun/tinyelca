/**************************************************************************
*  Copyright (c) 2021 by Michael Fischer (www.emb4fun.de).
*  All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without 
*  modification, are permitted provided that the following conditions 
*  are met:
*  
*  1. Redistributions of source code must retain the above copyright 
*     notice, this list of conditions and the following disclaimer.
*
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the 
*     documentation and/or other materials provided with the distribution.
*
*  3. Neither the name of the author nor the names of its contributors may 
*     be used to endorse or promote products derived from this software 
*     without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
*  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
*  THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
*  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
*  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
*  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
*  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
*  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
*  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
*  SUCH DAMAGE.
*
***************************************************************************
*  History:
*
*  24.04.2021  mifi  First Version.
**************************************************************************/
#define __ELCA_C__

/*
 * Sorry for the mixed code formatting. 
 * Generally I use "Pascal Case" but Mbed TLS use "Snake Case".
 */ 

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "tal.h"
#include "tcts.h"
#include "ipweb.h"
#include "fsapi.h"
#include "ff.h"
#include "elca.h"
#include "elca_rpc.h"
#include "terminal.h"
#include "ipstack.h"

#include "mbedtls/platform.h"
#include "mbedtls/base64.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

/*lint -save -e801*/

/*=======================================================================*/
/*  Extern                                                               */
/*=======================================================================*/

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

/*
 * CRT validity
 */
#define CRT_VALID_DAYS  (365 * 2) 

/*
 * Some external swithes are not ready to use if the link
 * is available. Therefore wait a short time.
 */
#define DELAY_AFTER_LINK_MS   2000

/*
 * End macro
 */
#define GOTO_END(_a)  { rc = _a; goto end; }

/*
 * Policy mask
 */
#define SIZE_OK         0x01
#define UPPERCASE_OK    0x02
#define LOWERCASE_OK    0x04
#define NUMBER_OK       0x08
#define SYMBOL_OK       0x10

/*
 * Status infos
 */
#define STATUS_MUST_INIT         -1
#define STATUS_UNLOCKED          0
#define STATUS_LOCKED            1

/*
 * Error infos
 */
//#define ELCA_OK                  0
//#define ELCA_ERROR               -1
#define ELCA_ERR_NO_INIT         -2
#define ELCA_ERR_PASS_POLICY     -3
#define ELCA_ERR_NO_LOCKED       -4
#define ELCA_ERR_PASS_WRONG      -5
#define ELCA_ERR_NO_UNLOCK       -6
#define ELCA_ERR_KEY_POLICY      -7
#define ELCA_ERR_INVALID_CSR     -8
#define ELCA_ERR_INVALID_CRT     -9

#define ELCA_ERR_ELCA_PATH       -100
#define ELCA_ERR_PKCS5           -101
#define ELCA_ERR_AES             -102
#define ELCA_ERR_ELCA_KEY_WRITE  -103


#define ELCA_ERR_CSR_SUBJECT     -200
#define ELCA_ERR_CSR_CN          -201
#define ELCA_ERR_CSR_O           -202
#define ELCA_ERR_CSR_OU          -203
#define ELCA_ERR_CSR_C           -204
#define ELCA_ERR_CSR_AN          -205

#define ELCA_ERR_CRT_SUBJECT     -300
#define ELCA_ERR_CRT_ISSUER      -301 
#define ELCA_ERR_CRT_CN          -302
#define ELCA_ERR_CRT_O           -303
#define ELCA_ERR_CRT_OU          -304
#define ELCA_ERR_CRT_C           -305
#define ELCA_ERR_CRT_AN          -306
#define ELCA_ERR_CRT_IC          -307
#define ELCA_ERR_CRT_IO          -308
#define ELCA_ERR_CRT_ICN         -309
#define ELCA_ERR_CRT_S           -310

/*
 * ELCA keylen, will be used for AES too
 */
#define ELCA_KEY_LEN       32
#define AES_IV_BYTES_CNT   16
#define AES_DATA_BYTES_CNT 16


typedef struct _oid_an_
{
   uint8_t  OID[3];
   uint8_t  OIDType;
   uint8_t  OIDLen;
   uint8_t  DataType;
   uint8_t  DataLen;
   uint8_t  Data;
} OID_AN;

typedef struct _cert_
{
   mbedtls_x509_crt crt;
   char             raw[2048];
   char             CN[256];
   char             O[256];
   char             C[256];
   char             NB[256];
   char             NA[256];
   char             ICN[256];
   char             IO[256];
   char             IC[256];
   char             S[256];
} CERT;


#define SAN_TAG_LIST_CNT      16
#define MBEDTLS_SAN_MAX_LEN   64

typedef struct _san_tag_
{
   uint8_t  tag;
   size_t   hostlen;
   char    *host;
   uint32_t address;
} SAN_TAG;


#define DEV_CRT_LIST_CNT   8
#define DEV_CRT_DATA_SIZE  1024

typedef struct _devcrt_
{
   uint32_t id;
   char     crt_data[DEV_CRT_DATA_SIZE];
} DEVCRT;


#define PSK_LEN            32

/*=======================================================================*/
/*  Definition of all global Data                                        */
/*=======================================================================*/

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

/* 
 * Some TASK variables like stack and task control block.
 */
static OS_STACK (ELCAStack, TASK_IP_ELCA_STK_SIZE);
static OS_TCB TCBELCA;

static OS_SEMA Sema;

static uint8_t ELCAKey[ELCA_KEY_LEN];
static uint8_t ELCASalt[] = "TinyELCA";
static uint8_t ELCATest[] = "TinyELCA";   /* Must have a size of less or equal to 15 chars */
static uint8_t PSK[PSK_LEN + 1];
static int    nELCAStatus = STATUS_MUST_INIT;
static int    nCAKeyNotFound = 1;
static int    nPSKNotFound   = 1;

static mbedtls_x509_csr         csr; 
static mbedtls_x509_crt         crt;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context  entropy;

static char Month[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static CERT                RootCert;
static CERT                InterCert;
static mbedtls_pk_context  InterKey;

static const uint8_t server_outh[] = { 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };

static DEVCRT  DevCRTList[DEV_CRT_LIST_CNT];
static uint8_t DevCrtListIndex = 0;

/*=======================================================================*/
/*  Definition of all local Procedures                                   */
/*=======================================================================*/

/*lint -save -e717 -e737*/

static int mbedtls_x509write_crt_set_subject_alternative_name (mbedtls_x509write_cert *pCRT, SAN_TAG *pSanList, int SanCntMax)
{
   int	         ret = 0;
   SAN_TAG       *cur;
   unsigned char *buf;
   unsigned char *pc;
   size_t len;
   size_t buflen;

   /* How many DNS names to be written */
   if (0 == SanCntMax)
      return ret;

   buflen = (size_t)(MBEDTLS_SAN_MAX_LEN * SanCntMax);
   buf = mbedtls_calloc(1, buflen);
   if (!buf)
      return MBEDTLS_ERR_ASN1_ALLOC_FAILED;

   //mbedtls_zeroize(buf, buflen);
   memset(buf, 0x00, buflen);
   pc = buf + buflen;

   len = 0;
   for (int x = (SanCntMax-1); x >= 0; x--)
   {
      /* Start at the end of the list to 0 */ 
      cur = &pSanList[x];
      
      if (0x82 == cur->tag)
      {
         MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)cur->host, cur->hostlen));
         MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, cur->hostlen));
         MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2));
      }
      
      if (0x87 == cur->tag)
      {
         MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&pc, buf, (const unsigned char *)&cur->address, sizeof(cur->address)));
         MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, sizeof(cur->address)));
         MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7));
      }
   }      

   MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&pc, buf, len));
   MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&pc, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

   ret = mbedtls_x509write_crt_set_extension(pCRT,
                                             MBEDTLS_OID_SUBJECT_ALT_NAME,
                                             MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                                             0,
                                             buf + buflen - len,
                                             len);
   mbedtls_free(buf);
   
   return(ret);
} /* mbedtls_x509write_crt_set_subject_alternative_name */

/*lint -restore*/

/*************************************************************************/
/*  CreateValidity                                                       */
/*                                                                       */
/*  In    : not_before, not_after                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static void CreateValidity (char not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN], 
                            char not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN])
{
   time_t    Unixtime;
   struct tm TM;

   Unixtime = (time_t)OS_UnixtimeGet();
   gmtime_r(&Unixtime, &TM);
   
   snprintf(not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN, "%4d%02d%02d%02d%02d%02d",
            TM.tm_year + 1900, TM.tm_mon + 1, TM.tm_mday,
            TM.tm_hour, TM.tm_min, TM.tm_sec);
            
   Unixtime += (time_t)(CRT_VALID_DAYS * 24 * 60 * 60);
   gmtime_r(&Unixtime, &TM);
            
   snprintf(not_after,  MBEDTLS_X509_RFC5280_UTC_TIME_LEN, "%4d%02d%02d%02d%02d%02d",
            TM.tm_year + 1900, TM.tm_mon + 1, TM.tm_mday,
            TM.tm_hour, TM.tm_min, TM.tm_sec);

} /* CreateValidity */

/*************************************************************************/
/*  LoadPSK                                                              */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int LoadPSK (void)
{
   int                        rc = -1;
   int                        fd;
   int                        size;
   char                      *chr;
   static mbedtls_aes_context ctx;
   static uint8_t             data[1024];
   static uint8_t             iv[AES_IV_BYTES_CNT];
   static uint8_t             tmp[AES_IV_BYTES_CNT];
   FRESULT                    res;
   FIL                        fil;
   uint32_t                   bw;
   
   
   nPSKNotFound = 1;

   /* 
    * Check if a PSK is available 
    */
   fd = _open("SD0:/elca/psk.txt",  _O_BINARY | _O_RDONLY);
   if (fd != -1)
   {
      /* Read the key */
      memset(data, 0x00, sizeof(data));
      _read(fd, data, sizeof(data));
      _close(fd);
      
      /* Check if this is a valid key, no space or \r\n allowed */
      chr = strstr((char*)data, " ");
      if (chr != NULL) *chr = 0;
      
      /* And no \r\n */
      chr = (char*)data;
      while (*chr != 0)
      {
         if ((0x0A == *chr) || (0x0D == *chr))
         {
            *chr = 0;
            break;
         }
         chr++;
      }
      size = (int)strlen((char*)data);
      if (size > PSK_LEN)
      {
         data[PSK_LEN] = 0;
      }          
      
      /* 
       * The PSK must be encrypted 
       */
      /* Align to AES_DATA_BYTES_CNT */
      size  = ((size + (AES_DATA_BYTES_CNT-1)) & ~(AES_DATA_BYTES_CNT-1));

      /* Get IV bytes */
      tal_CPURngHardwarePoll(tmp, AES_IV_BYTES_CNT);
      
      /* Encrypt data */
      memcpy(iv, tmp, AES_IV_BYTES_CNT);
      mbedtls_aes_init(&ctx);
      mbedtls_aes_setkey_enc(&ctx, ELCAKey, (ELCA_KEY_LEN*8));
      rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 
                                 (size_t)size,
                                 iv,
                                 (uint8_t*)data,
                                 (uint8_t*)data);
      mbedtls_aes_free(&ctx);
      
      /* Check for AES error */
      if (rc != 0) GOTO_END(ELCA_ERROR);
      
      /* Write encrypted key */
      fd = _open("SD0:/elca/psk.key", _O_BINARY | _O_WRONLY | _O_APPEND);
      if (fd != -1)
      {
         rc  = _write(fd, tmp, AES_IV_BYTES_CNT);
         rc += _write(fd, data, (size_t)size);
         _close(fd);
         if (rc != (int)(AES_IV_BYTES_CNT + size))  GOTO_END(ELCA_ERROR);
      } 
      
      /* 
       * Overwrite and delete "psk.txt"
       */

      /* Remove read-only attribute */       
      f_chmod("elca/psk.txt", 0, AM_RDO);
       
      /* Overwrite */ 
      res = f_open(&fil, "elca/psk.txt", FA_READ | FA_WRITE);
      if (FR_OK == res)
      {  
         memset(data, 0x00, sizeof(data));
         size = (int)f_size(&fil);
         f_lseek(&fil, 0);
         res = f_write (&fil, data, (UINT)size, &bw);
         f_close(&fil);
      }
      
      /* Delete */
      f_unlink("elca/psk.txt");
      
   } /* end if "Check if a PEM key ist available" */
   

   /* 
    * Check if an encrypted PSK is available 
    */
   fd = _open("SD0:/elca/psk.key",  _O_BINARY | _O_RDONLY);
   if (fd != -1)
   {
      memset(data, 0x00, sizeof(data));
      size = _read(fd, data, sizeof(data));
      _close(fd);

      /* Get AES Data size */      
      size -= AES_IV_BYTES_CNT;
      if (size < 0) GOTO_END(ELCA_ERROR);

      /* Decrypt data */
      mbedtls_aes_init(&ctx);
      mbedtls_aes_setkey_dec(&ctx, ELCAKey, (ELCA_KEY_LEN*8));
      rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 
                                 (size_t)size,
                                 data,
                                 (uint8_t*)&data[AES_IV_BYTES_CNT],
                                 (uint8_t*)&data[AES_IV_BYTES_CNT]);
      mbedtls_aes_free(&ctx);
      
      /* Check for AES error */
      if (rc != 0) GOTO_END(ELCA_ERROR);
      
      /* Get KEY size */
      size = (int)strlen((char*)&data[AES_IV_BYTES_CNT]);
      if (size > PSK_LEN) GOTO_END(ELCA_ERROR);
      memset(PSK, 0x00, sizeof(PSK));
      memcpy(PSK, (char*)&data[AES_IV_BYTES_CNT], (size_t)size);
      
      /* No error */   
      nPSKNotFound = 0;
   }      

end:  

   return(rc);   
} /* LoadPSK */

/*************************************************************************/
/*  LoadCAKey                                                            */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int LoadCAKey (void)
{
   int                        rc = -1;
   int                        fd;
   int                        size;
   static mbedtls_aes_context ctx;
   static uint8_t             data[1024];
   static uint8_t             iv[AES_IV_BYTES_CNT];
   static uint8_t             tmp[AES_IV_BYTES_CNT];
   FRESULT                    res;
   FIL                        fil;
   uint32_t                   bw;
   
   
   mbedtls_pk_init(&InterKey);
   
   nCAKeyNotFound = 1;

   /* 
    * Check if a PEM key is available 
    */
   fd = _open("SD0:/elca/inter.pem",  _O_BINARY | _O_RDONLY);
   if (fd != -1)
   {
      /* Read the key */
      memset(data, 0x00, sizeof(data));
      size = _read(fd, data, sizeof(data));
      _close(fd);
      size++;      
      
      /* Check if this is a valid key */
      rc = mbedtls_pk_parse_key(&InterKey, data, (size_t)size, NULL, 0);
      if (rc != 0) GOTO_END(ELCA_ERROR);
      mbedtls_pk_free(&InterKey);
      
      /* 
       * The PEM key must be encrypted 
       */
      /* Align to AES_DATA_BYTES_CNT */
      size  = ((size + (AES_DATA_BYTES_CNT-1)) & ~(AES_DATA_BYTES_CNT-1));

      /* Get IV bytes */
      tal_CPURngHardwarePoll(tmp, AES_IV_BYTES_CNT);
      
      /* Encrypt data */
      memcpy(iv, tmp, AES_IV_BYTES_CNT);
      mbedtls_aes_init(&ctx);
      mbedtls_aes_setkey_enc(&ctx, ELCAKey, (ELCA_KEY_LEN*8));
      rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 
                                 (size_t)size,
                                 iv,
                                 (uint8_t*)data,
                                 (uint8_t*)data);
      mbedtls_aes_free(&ctx);
      
      /* Check for AES error */
      if (rc != 0) GOTO_END(ELCA_ERROR);
      
      /* Write encrypted key */
      fd = _open("SD0:/elca/inter.key", _O_BINARY | _O_WRONLY | _O_APPEND);
      if (fd != -1)
      {
         rc  = _write(fd, tmp, AES_IV_BYTES_CNT);
         rc += _write(fd, data, (size_t)size);
         _close(fd);
         if (rc != (int)(AES_IV_BYTES_CNT + size))  GOTO_END(ELCA_ERROR);
      } 
      
      /* 
       * Overwrite and delete PEM key 
       */

      /* Remove read-only attribute */       
      f_chmod("elca/inter.pem", 0, AM_RDO);
       
      /* Overwrite */ 
      res = f_open(&fil, "elca/inter.pem", FA_READ | FA_WRITE);
      if (FR_OK == res)
      {  
         memset(data, 0x00, sizeof(data));
         size = (int)f_size(&fil);
         f_lseek(&fil, 0);
         res = f_write (&fil, data, (UINT)size, &bw);
         f_close(&fil);
      }
      
      /* Delete */
      f_unlink("elca/inter.pem");
      
   } /* end if "Check if a PEM key ist available" */
   

   /* 
    * Check if an encrypted key is available 
    */
   fd = _open("SD0:/elca/inter.key",  _O_BINARY | _O_RDONLY);
   if (fd != -1)
   {
      memset(data, 0x00, sizeof(data));
      size = _read(fd, data, sizeof(data));
      _close(fd);

      /* Get AES Data size */      
      size -= AES_IV_BYTES_CNT;
      if (size < 0) GOTO_END(ELCA_ERROR);

      /* Decrypt data */
      mbedtls_aes_init(&ctx);
      mbedtls_aes_setkey_dec(&ctx, ELCAKey, (ELCA_KEY_LEN*8));
      rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 
                                 (size_t)size,
                                 data,
                                 (uint8_t*)&data[AES_IV_BYTES_CNT],
                                 (uint8_t*)&data[AES_IV_BYTES_CNT]);
      mbedtls_aes_free(&ctx);
      
      /* Check for AES error */
      if (rc != 0) GOTO_END(ELCA_ERROR);
      
      /* Get KEY size */
      size = (int)strlen((char*)&data[AES_IV_BYTES_CNT]) + 1;
      if (size > ((int)sizeof(data) - AES_IV_BYTES_CNT)) GOTO_END(ELCA_ERROR);
         
      /* Check if this is a valid key */
      mbedtls_pk_init(&InterKey);
      rc = mbedtls_pk_parse_key(&InterKey, &data[AES_IV_BYTES_CNT], (size_t)size, NULL, 0);
      if (rc != 0) GOTO_END(ELCA_ERROR);
      
      /* No error */   
      nCAKeyNotFound = 0;
   }      

end:  

   if (rc != 0)
   {
      mbedtls_pk_free(&InterKey);
   } 

   return(rc);   
} /* LoadCAKey */

/*************************************************************************/
/*  ConvertTextarea                                                      */
/*                                                                       */
/*  Converting the textarea data by replacing the two characters "\n"    */
/*  by 0x0D 0x0A.                                                        */
/*                                                                       */
/*  In    : pData                                                        */
/*  Out   : pData                                                        */
/*  Return: none                                                         */
/*************************************************************************/
static void ConvertTextarea (char *pData)
{
   pData = strstr(pData, "\\n");
   while (pData != NULL)
   {
      pData[0] = 0x0D;
      pData[1] = 0x0A;
      pData += 2;
      pData = strstr(pData, "\\n");
   }

} /* ConvertTextarea */

/*************************************************************************/
/*  GetSubjectTag                                                        */
/*                                                                       */
/*  Find "Alternative Names".                                            */
/*                                                                       */
/*  In    : pSubject, pTag, pBuffer, Size                                */
/*  Out   : pBuffer                                                      */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int GetSubjectTag (char *pSubject, char *pTag, char *pBuffer, size_t BufferSize)
{
   int     rc = ELCA_ERROR;
   size_t  Size;
   char   *p;
   
   memset(pBuffer, 0x00, BufferSize);

   p = strstr(pSubject, pTag);
   if (p != NULL)
   {
      p += strlen(pTag);
      Size = 0;
      while ((*p != ',') && (Size < BufferSize))
      {
         pBuffer[Size++] = *p++;
      }
      rc = ELCA_OK;
   }      
   
   return(rc);
} /* GetSubjectTag */

/*************************************************************************/
/*  GetANStr                                                             */
/*                                                                       */
/*  Find "Alternative Names".                                            */
/*                                                                       */
/*  In    : pData, DataSize, pSanList, SanMaxCnt                         */
/*  Out   : pSanList                                                     */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int GetANBin (uint8_t *pData, size_t DataSize, SAN_TAG *pSanList, int SanMaxCnt)
{
   int        SanCnt = 0;
   int        rc = ELCA_ERR_CSR_AN;
   int        DataLen;
   uint8_t    Len;
   uint8_t   *p = NULL;
   OID_AN    *pAN;
   
   /* Clear data first */   
   memset(pSanList, 0x00, (sizeof(SAN_TAG) * (size_t)SanMaxCnt));
   
   for (size_t x = 0; x < DataSize; x++)
   {
      if( (0x55 == pData[x + 0]) && 
          (0x1D == pData[x + 1]) && 
          (0x11 == pData[x + 2]) && 
          (0x04 == pData[x + 3]) ) 
      {
         p = &pData[x];
         break;
      }          
   }
   
   if (p != NULL)
   {
      rc = ELCA_OK;
      
      /*lint -save -e527 -e661 -e662 -e826*/
   
      pAN = (OID_AN*)p;
      
      (void)pAN->OID;      /* Prevent lint warning */
      (void)pAN->OIDType;
      (void)pAN->OIDLen;   
      (void)pAN->DataType;
      
      SanCnt  = 0;
      DataLen = pAN->DataLen;
      pData   = &pAN->Data;
      while ((DataLen > 0) && (SanCnt < SanMaxCnt))
      {
         switch (*pData++)
         {
            case 0x82:  /* DNS: Copy string */
            {
               Len = *pData++;
               
               pSanList->tag     = 0x82;
               pSanList->hostlen = Len;
               pSanList->host    = (char*)pData;
               
               pData   += Len;
               DataLen -= 2;
               DataLen -= (int)Len;
               
               pSanList++;
               SanCnt++;
               break;
            }
            case 0x87:  /* IP: Copy string */
            {
               Len = *pData++;
               
               pSanList->tag     = 0x87;
               pSanList->address = *((uint32_t*)pData);
               
               pData   += Len;
               DataLen -= 2;
               DataLen -= Len;

               pSanList++;
               SanCnt++;
               break;               
            }
            default:
            {
               GOTO_END(ELCA_ERR_CSR_AN);
               break;
            }
         }
      }
      /*lint -restore*/
      
   }
   
   /* Get SAN count */
   if (ELCA_OK == rc)
   {
      rc = SanCnt;
   }
   
end:   
   
   return(rc);
} /* GetANBin */

/*************************************************************************/
/*  GetANStr                                                             */
/*                                                                       */
/*  Find "Alternative Names".                                            */
/*                                                                       */
/*  In    : pData, DataSize, pBuffer, BufferSize                         */
/*  Out   : pBuffer                                                      */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int GetANStr (uint8_t *pData, size_t DataSize, char *pBuffer, size_t BufferSize)
{
   int        rc = ELCA_ERR_CSR_AN;
   int        DataLen;
   uint8_t    Len;
   size_t     x;
   uint8_t   *p = NULL;
   OID_AN    *pAN;
   static char Tmp[256];
   
   memset(pBuffer, 0x00, sizeof(BufferSize));
   
   for (x = 0; x < DataSize; x++)
   {
      if( (0x55 == pData[x + 0]) && 
          (0x1D == pData[x + 1]) && 
          (0x11 == pData[x + 2]) && 
          (0x04 == pData[x + 3]) ) 
      {
         p = &pData[x];
         break;
      }          
   }
   
   if (p != NULL)
   {
      rc = ELCA_OK;
      
      /*lint -save -e527 -e661 -e662 -e826*/
   
      pAN = (OID_AN*)p;
      
      (void)pAN->OID;      /* Prevent lint warning */
      (void)pAN->OIDType;
      (void)pAN->OIDLen;   
      (void)pAN->DataType;
      
      DataLen = pAN->DataLen;
      pData   = &pAN->Data;
      while ((DataLen > 0) && (strlen(pBuffer) < BufferSize))
      {
         switch (*pData++)
         {
            case 0x82:  /* DNS: Copy string */
            {
               Len = *pData++;
               strncpy(Tmp, (char*)pData, Len);
               Tmp[Len] = 0;
               pData += Len;
               
               DataLen -= 2;
               DataLen -= (int)Len;
               
               if ((strlen(pBuffer) + Len + 1) < BufferSize)
               {
                  strcat(pBuffer, Tmp);
                  strcat(pBuffer, " ");
               }
               else
               {
                  GOTO_END(ELCA_ERR_CSR_AN);
               }   
               break;
            }
            case 0x87:  /* IP: Copy string */
            {
               Len = *pData++;
               snprintf(Tmp, sizeof(Tmp), "%d.%d.%d.%d ", 
                        pData[0], pData[1], pData[2], pData[3]);
               pData += Len;                        

               DataLen -= 2;
               DataLen -= Len;

               if ((strlen(pBuffer) + strlen(Tmp) + 1) < BufferSize)
               {
                  strcat(pBuffer, Tmp);
               }
               else
               {
                  GOTO_END(ELCA_ERR_CSR_AN);
               }   
               break;               
            }
            default:
            {
               GOTO_END(ELCA_ERR_CSR_AN);
               break;
            }
         }
      }
      /*lint -restore*/
      
      /* Remove space from the end of the string */
      DataLen = (int)strlen(pBuffer);
      if (' ' == pBuffer[DataLen-1])
      {
         pBuffer[DataLen-1] = 0;
      }
   }
   
end:   
   
   return(rc);
} /* GetANStr */

/*************************************************************************/
/*  CRTCreate                                                            */
/*                                                                       */
/*  In    : pCSR, crt_data, crt_data_size, id                            */
/*  Out   : crt_data                                                     */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CRTCreate (char *pCSR, char *crt_data, size_t crt_data_size, uint32_t id, int textarea)
{
   int                           rc;
   size_t                        size;
   mbedtls_mpi                   serial;
   static char                   subject_name[256];
   static char                   issuer_name[256];
   static char                   serial_name[256];
   static uint8_t                serial_raw[16];
   static char                   not_before[MBEDTLS_X509_RFC5280_UTC_TIME_LEN];
   static char                   not_after[MBEDTLS_X509_RFC5280_UTC_TIME_LEN];
   static char                   tmp[3];
   mbedtls_pk_context           *subject_key;
   static mbedtls_x509write_cert crt;  /*lint !e578*/
   int                           san_cnt;
   static SAN_TAG                san_list[SAN_TAG_LIST_CNT];
   
   (void)id;

   if (1 == textarea)
   {
      ConvertTextarea(pCSR);
   }   
   size = strlen(pCSR) + 1;   

   mbedtls_x509_csr_init(&csr);
   mbedtls_x509write_crt_init(&crt);
   mbedtls_ctr_drbg_init(&ctr_drbg);
   mbedtls_entropy_init(&entropy);
   mbedtls_mpi_init(&serial);

   /* Create entropy */
   rc =  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)"TinyELCA", 7);
   if (rc != 0) GOTO_END(rc);

   /* Get issuer name */   
   rc = mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &InterCert.crt.subject);
   if (rc < 0) GOTO_END(rc);
   
   /*******************************************************************/

   /*
    * Parse CSR
    */
   rc = mbedtls_x509_csr_parse(&csr, (uint8_t*)pCSR, size);
   if (rc != 0) GOTO_END(rc);
   
   san_cnt = GetANBin(csr.raw.p, csr.raw.len, san_list, SAN_TAG_LIST_CNT);
   if (san_cnt < 0) GOTO_END(san_cnt);

   rc = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &csr.subject);
   if (rc < 0) GOTO_END(rc);

   subject_key = &csr.pk;

   /*******************************************************************/

   /*
    * setup CRT
    */
    
   /* Subject and Issuer key */ 
   mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
   mbedtls_x509write_crt_set_issuer_key(&crt, &InterKey);

   /* Subject and Issuer name */
   rc = mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
   if (rc != 0) GOTO_END(rc);

   rc = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name);
   if (rc != 0) GOTO_END(rc);

   /* Version and signature algorithm */
   mbedtls_x509write_crt_set_version(&crt, 3-1);
   mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

   /* Serial number */
   serial_name[0] = 0;
   tal_CPURngHardwarePoll(serial_raw, sizeof(serial_raw));
   for (int x = 0; x < (int)sizeof(serial_raw); x++)
   {
      snprintf(tmp, sizeof(tmp), "%02x", serial_raw[x]);
      strcat(serial_name, tmp);
   }
   rc = mbedtls_mpi_read_string(&serial, 16, serial_name);
   if (rc != 0) GOTO_END(rc);

   rc = mbedtls_x509write_crt_set_serial(&crt, &serial);
   if (rc != 0) GOTO_END(rc);

   /* Validity */
   CreateValidity(not_before, not_after);
   rc = mbedtls_x509write_crt_set_validity(&crt, not_before, not_after);
   if (rc != 0) GOTO_END(rc);

   /* Basic contraints */
   rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
   if (rc != 0) GOTO_END(rc);

   /* Key usgae */
   rc = mbedtls_x509write_crt_set_key_usage(&crt, 
                                            MBEDTLS_X509_KU_DIGITAL_SIGNATURE | 
                                            MBEDTLS_X509_KU_KEY_ENCIPHERMENT );
   if (rc != 0) GOTO_END(rc);

   /* Subject alternative names */
   rc = mbedtls_x509write_crt_set_subject_alternative_name(&crt, san_list, san_cnt);
   if (rc != 0) GOTO_END(rc);

   /* Extended key usage */
   rc = mbedtls_x509write_crt_set_extension(&crt,
                                             MBEDTLS_OID_EXTENDED_KEY_USAGE , MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
                                             0,
                                             server_outh, sizeof(server_outh));
   if (rc != 0) GOTO_END(rc);

   /* Create certificate in PEM format */
   memset(crt_data, 0x00, crt_data_size );
   rc = mbedtls_x509write_crt_pem(&crt, (uint8_t*)crt_data, crt_data_size, mbedtls_ctr_drbg_random, &ctr_drbg);
   if (rc < 0) return(rc);
   
   /* Store device certificate for later use */
   if (strlen(crt_data)+1 < DEV_CRT_DATA_SIZE)
   {
      DevCRTList[DevCrtListIndex].id = id;
      memcpy(DevCRTList[DevCrtListIndex].crt_data, crt_data, strlen(crt_data)+1);
      
      DevCrtListIndex++;
      if (DevCrtListIndex >= DEV_CRT_LIST_CNT)
      {
         DevCrtListIndex = 0;
      }
   }      
   
   rc = ELCA_OK;
   
end:

   mbedtls_x509_csr_free(&csr);
   mbedtls_x509write_crt_free(&crt);
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);
   mbedtls_mpi_free(&serial);

   return(rc);   
} /* CRTCreate */

/*************************************************************************/
/*  CRTDecodeStr                                                         */
/*                                                                       */
/*  In    : pFilename, pCert                                             */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CRTDecodeStr (char *pFilename, CERT *pCert)
{
   int         rc = ELCA_ERROR;
   int         fd;
   size_t      size;
   static char subject_name[256];
   static char issuer_name[256];

   mbedtls_x509_crt_init(&pCert->crt);

   /* Read "key" */
   fd = _open(pFilename, _O_BINARY | _O_RDONLY);
   if (-1 == fd) GOTO_END(ELCA_ERROR);
   size = (size_t)_read(fd, pCert->raw, sizeof(pCert->raw));
   _close(fd);
   size++;
   
   if (size < sizeof(pCert->raw))
   {
      /* Parse CRT */
      rc = mbedtls_x509_crt_parse(&pCert->crt, (uint8_t*)pCert->raw, size);
      if (rc != 0) GOTO_END(ELCA_ERR_INVALID_CRT);

      rc = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &pCert->crt.subject);
      if (rc < 0) GOTO_END(ELCA_ERR_CRT_SUBJECT);

      rc = mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &pCert->crt.issuer);
      if (rc < 0) GOTO_END(ELCA_ERR_CRT_ISSUER);
   
      /* Find "Common Name" */
      rc = GetSubjectTag(subject_name, "CN=", pCert->CN, sizeof(pCert->CN));
      if (rc != 0) GOTO_END(ELCA_ERR_CRT_CN);

      /* Find "Organization" */
      rc = GetSubjectTag(subject_name, "O=", pCert->O, sizeof(pCert->O));
      if (rc != 0) GOTO_END(ELCA_ERR_CRT_O);

      /* Find "Country" */
      rc = GetSubjectTag(subject_name, "C=", pCert->C, sizeof(pCert->C));
      if (rc != 0) GOTO_END(ELCA_ERR_CRT_C);
   
      /* Find "Issuer Country" */
      rc = GetSubjectTag(issuer_name, "C=", pCert->IC, sizeof(pCert->IC));
      if (rc != 0) GOTO_END(ELCA_ERR_CRT_IC);

      /* Find "Issuer Organization" */
      rc = GetSubjectTag(issuer_name, "O=", pCert->IO, sizeof(pCert->IO));
      if (rc != 0) GOTO_END(ELCA_ERR_CRT_IO);
   
      /* Find "Issuer Common Name" */
      rc = GetSubjectTag(issuer_name, "CN=", pCert->ICN, sizeof(pCert->ICN));
      if (rc != 0) GOTO_END(ELCA_ERR_CRT_ICN);
   
      /* Not before */
      snprintf(pCert->NB, sizeof(pCert->NB), "%s %2d %02d:%02d:%02d %04d GMT", 
               Month[pCert->crt.valid_from.mon-1], pCert->crt.valid_from.day,
               pCert->crt.valid_from.hour, pCert->crt.valid_from.min, pCert->crt.valid_from.sec, 
               pCert->crt.valid_from.year);

      /* Not after */
      snprintf(pCert->NA, sizeof(pCert->NA), "%s %2d %02d:%02d:%02d %04d GMT", 
               Month[pCert->crt.valid_to.mon-1], pCert->crt.valid_to.day,
               pCert->crt.valid_to.hour, pCert->crt.valid_to.min, pCert->crt.valid_to.sec, 
               pCert->crt.valid_to.year);

      /* Serial number */   
      rc = mbedtls_x509_serial_gets(pCert->S, sizeof(pCert->S), &pCert->crt.serial);
      if (rc < 0) GOTO_END(ELCA_ERR_CRT_S);
   
      rc = 0;
   }

end:

   if (rc != 0)
   {
      mbedtls_x509_crt_free(&pCert->crt);
   }      
   
   return(rc);
} /* CRTDecodeStr */

/*************************************************************************/
/*  CSRDecode                                                            */
/*                                                                       */
/*  In    : hs, pCSR                                                     */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CSRDecode (HTTPD_SESSION *hs, char *pCSR)
{
   int         rc;
   size_t      size;
   static char subject_name[256];
   static char CN[256];
   static char AN[256];
   static char O[256];
   static char OU[256];
   static char C[256];

   mbedtls_x509_csr_init(&csr);
   
   ConvertTextarea(pCSR);
   size = strlen(pCSR) + 1;   
   
   /* Parse CSR */
   rc = mbedtls_x509_csr_parse(&csr, (uint8_t*)pCSR, size);
   if (rc != 0) GOTO_END(ELCA_ERR_INVALID_CSR);

   rc = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &csr.subject);
   if (rc < 0) GOTO_END(ELCA_ERR_CSR_SUBJECT);

   /* Find "Common Name" */
   rc = GetSubjectTag(subject_name, "CN=", CN, sizeof(CN));
   if (rc != 0) GOTO_END(ELCA_ERR_CSR_CN);

   /* Find "Organization" */
   rc = GetSubjectTag(subject_name, "O=", O, sizeof(O));
   if (rc != 0) GOTO_END(ELCA_ERR_CSR_O);

   /* Find "Organization Unit" */
   rc = GetSubjectTag(subject_name, "OU=", OU, sizeof(OU));
   if (rc != 0) GOTO_END(ELCA_ERR_CSR_OU);

   /* Find "Country" */
   rc = GetSubjectTag(subject_name, "C=", C, sizeof(C));
   if (rc != 0) GOTO_END(ELCA_ERR_CSR_C);
   
   /* Special check for "Alternative Names" */
   rc = GetANStr(csr.raw.p, csr.raw.len, AN, sizeof(AN));
   if (rc != 0) GOTO_END(ELCA_ERR_CSR_AN);

   
   s_puts("{", hs->s_stream);
   s_printf(hs->s_stream, "\"cn\":\"%s\",", CN);
   s_printf(hs->s_stream, "\"an\":\"%s\",", AN);
   s_printf(hs->s_stream, "\"o\":\"%s\",", O);
   s_printf(hs->s_stream, "\"ou\":\"%s\",", OU);
   s_printf(hs->s_stream, "\"c\":\"%s\"", C);
   s_puts("}", hs->s_stream);
   s_flush(hs->s_stream);

   rc = 0;

end:

   mbedtls_x509_csr_free(&csr);
   
   return(rc);
} /* CSRDecode */

/*************************************************************************/
/*  CRTDecode                                                            */
/*                                                                       */
/*  In    : hs, pCRT                                                     */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CRTDecode (HTTPD_SESSION *hs, char *pCRT)
{
   int         rc;
   size_t      size;
   static char subject_name[256];
   static char issuer_name[256];
   static char CN[256];
   static char AN[256];
   static char O[256];
   static char OU[256];
   static char C[256];
   static char IC[256];
   static char IO[256];
   static char ICN[256];
   static char vf[256];
   static char vt[256];
   static char i[256];
   static char s[256];

   mbedtls_x509_crt_init(&crt);
   
   ConvertTextarea(pCRT);
   size = strlen(pCRT) + 1;   
   
   /* Parse CRT */
   rc = mbedtls_x509_crt_parse(&crt, (uint8_t*)pCRT, size);
   if (rc != 0) GOTO_END(ELCA_ERR_INVALID_CRT);

   rc = mbedtls_x509_dn_gets(subject_name, sizeof(subject_name), &crt.subject);
   if (rc < 0) GOTO_END(ELCA_ERR_CRT_SUBJECT);

   rc = mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &crt.issuer);
   if (rc < 0) GOTO_END(ELCA_ERR_CRT_ISSUER);
   
   /* Find "Common Name" */
   rc = GetSubjectTag(subject_name, "CN=", CN, sizeof(CN));
   if (rc != 0) GOTO_END(ELCA_ERR_CRT_CN);

   /* Find "Organization" */
   rc = GetSubjectTag(subject_name, "O=", O, sizeof(O));
   if (rc != 0) GOTO_END(ELCA_ERR_CRT_O);

   /* Find "Organization Unit" */
   rc = GetSubjectTag(subject_name, "OU=", OU, sizeof(OU));
   if (rc != 0) OU[0] = 0;
   //if (rc != 0) GOTO_END(ELCA_ERR_CRT_OU);

   /* Find "Country" */
   rc = GetSubjectTag(subject_name, "C=", C, sizeof(C));
   if (rc != 0) GOTO_END(ELCA_ERR_CRT_C);
   
   /* Special check for "Alternative Names" */
   rc = GetANStr(crt.raw.p, crt.raw.len, AN, sizeof(AN));
   if (rc != 0) AN[0] = 0;
   //if (rc != 0) GOTO_END(ELCA_ERR_CRT_AN);
   

   /* Find "Issuer Country" */
   rc = GetSubjectTag(issuer_name, "C=", IC, sizeof(IC));
   if (rc != 0) GOTO_END(ELCA_ERR_CRT_IC);

   /* Find "Issuer Organization" */
   rc = GetSubjectTag(issuer_name, "O=", IO, sizeof(IO));
   if (rc != 0) GOTO_END(ELCA_ERR_CRT_IO);
   
   /* Find "Issuer Common Name" */
   rc = GetSubjectTag(issuer_name, "CN=", ICN, sizeof(ICN));
   if (rc != 0) GOTO_END(ELCA_ERR_CRT_ICN);
   snprintf(i, sizeof(i), "%s, %s, %s", ICN, IO, IC);
   
   /* Not before */
   snprintf(vf, sizeof(vf), "%s %2d %02d:%02d:%02d %04d GMT", 
            Month[crt.valid_from.mon-1], crt.valid_from.day,
            crt.valid_from.hour, crt.valid_from.min, crt.valid_from.sec, 
            crt.valid_from.year);

   /* Not after */
   snprintf(vt, sizeof(vt), "%s %2d %02d:%02d:%02d %04d GMT", 
            Month[crt.valid_to.mon-1], crt.valid_to.day,
            crt.valid_to.hour, crt.valid_to.min, crt.valid_to.sec, 
            crt.valid_to.year);

   /* Serial number */   
   rc = mbedtls_x509_serial_gets(s, sizeof(s), &crt.serial);
   if (rc < 0) GOTO_END(ELCA_ERR_CRT_S);


   s_puts("{", hs->s_stream);
   s_printf(hs->s_stream, "\"cn\":\"%s\",", CN);
   s_printf(hs->s_stream, "\"an\":\"%s\",", AN);
   s_printf(hs->s_stream, "\"o\":\"%s\",", O);
   s_printf(hs->s_stream, "\"ou\":\"%s\",", OU);
   s_printf(hs->s_stream, "\"c\":\"%s\",", C);
   s_printf(hs->s_stream, "\"nb\":\"%s\",", vf);
   s_printf(hs->s_stream, "\"na\":\"%s\",", vt);
   s_printf(hs->s_stream, "\"i\":\"%s\",", i);
   s_printf(hs->s_stream, "\"s\":\"%s\"", s);
   s_puts("}", hs->s_stream);
   s_flush(hs->s_stream);

   rc = 0;

end:

   mbedtls_x509_crt_free(&crt);
   
   return(rc);
} /* CRTDecode */

/*************************************************************************/
/*  ELCACreateKey                                                        */
/*                                                                       */
/*  In    : pPass, PassLen                                               */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ELCACreateKey (char *pPass, size_t PassLen)
{
   int                      rc = ELCA_ERROR;
   int                      ret;
   mbedtls_md_context_t     sha2_ctx;
   const mbedtls_md_info_t *info_sha2;

   mbedtls_md_init(&sha2_ctx);

   info_sha2 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
   if (NULL == info_sha2) goto exit;

   if ((ret = mbedtls_md_setup(&sha2_ctx, info_sha2, 1)) != 0) goto exit;
   
   ret = mbedtls_pkcs5_pbkdf2_hmac(&sha2_ctx, 
                                   (uint8_t*)pPass, PassLen, 
                                   ELCASalt, sizeof(ELCASalt),
                                   4096,
                                   sizeof(ELCAKey), ELCAKey);
   if (0 == ret)
   {
      rc = ELCA_OK;
   }                                    

exit:

   mbedtls_md_free(&sha2_ctx);
   
   return(rc);
} /* ELCACreateKey */

/*************************************************************************/
/*  ELCAUnlock                                                           */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ELCAUnlock (void)
{
   int rc = ELCA_OK;

   /* Clear Root and Inter Str data */
   memset(&RootCert, 0x00, sizeof(RootCert));
   memset(&InterCert, 0x00, sizeof(InterCert));
   
   snprintf(RootCert.CN,  sizeof(RootCert.CN),  "The root certificate \"/elca/root.crt\" could not be found.");
   snprintf(InterCert.CN, sizeof(InterCert.CN), "The intermediate certificate \"/elca/inter.crt\" could not be found.");

   /* Decode certificates if available */   
   CRTDecodeStr("SD0:/elca/root.crt", &RootCert);
   CRTDecodeStr("SD0:/elca/inter.crt", &InterCert);
   
   return(rc);
} /* ELCAUnlock */

/*************************************************************************/
/*  ELCACheckInit                                                        */
/*                                                                       */
/*  Check if an ELCA is available.                                       */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void ELCACheckInit (void)
{
   int fd;
   
   /* Read "key" */
   fd = _open("SD0:/elca/elca.key", _O_BINARY | _O_RDONLY);
   if (fd != -1)
   {
      _close(fd);
   
      /* "key" is available, ELCA is locked */
      nELCAStatus = STATUS_LOCKED;
   }
   else
   {
      /* No "key", ELCA must init */
      nELCAStatus = STATUS_MUST_INIT;
   }

} /* ELCACheckInit */

/*************************************************************************/
/*  ELCAFirstInit                                                        */
/*                                                                       */
/*  In    : pPass, PassLen                                               */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ELCAFirstInit (char *pPass, size_t PassLen)
{
   int                        rc = ELCA_ERR_ELCA_PATH;
   FRESULT                    res;
   int                        fd;
   static mbedtls_aes_context ctx;
   static uint8_t             data[AES_DATA_BYTES_CNT];
   

   res = f_mkdir("elca");
   if ((FR_OK == res) || (FR_EXIST == res))
   {
      rc = ELCACreateKey(pPass, PassLen);
      if (rc != 0)
      {
         rc = ELCA_ERR_PKCS5;
      }
      else
      {
         /* Encrypt data */
         tal_CPURngHardwarePoll(data, sizeof(data));
         snprintf((char*)data, sizeof(data), "%s", ELCATest);
         
         mbedtls_aes_init(&ctx);
         mbedtls_aes_setkey_enc(&ctx, ELCAKey, (ELCA_KEY_LEN*8));
         rc = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, 
                                    (uint8_t*)data,
                                    (uint8_t*)data);
         mbedtls_aes_free(&ctx);
      
         /* Check for AES error */
         if (rc != 0)
         {
            rc = ELCA_ERR_AES;
         }
         else
         {
            /* No AES error, write the "key" */
            rc = ELCA_ERR_ELCA_KEY_WRITE; 
            fd = _open("SD0:/elca/elca.key", _O_BINARY | _O_WRONLY | _O_CREATE_ALWAYS);
            if (fd != -1)
            {
               rc = _write(fd, data, sizeof(data));
               _close(fd);
            
               /* Check write */
               if (rc == (int)sizeof(data))
               {
                  rc = ELCA_OK;
               }
            }
         }
      }            
   }

   return(rc);
} /* ELCAFirstInit */

/*************************************************************************/
/*  CheckPasswordRules                                                   */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CheckPasswordRules (char *pPass)
{
   int      rc = ELCA_ERR_PASS_POLICY;
   uint8_t bFlags = 0;

   #define PASS_MASK_OK 0x1F
   
   if (strlen(pPass) >= 8)
   {
      bFlags |= SIZE_OK;
      
      while (*pPass != 0)
      {
         /* Check uppercase */
         if      ((*pPass >= 'A') && (*pPass <= 'Z'))
         {
            bFlags |= UPPERCASE_OK;
         }
         /* Check lowercase */
         else if ((*pPass >= 'a') && (*pPass <= 'z'))
         {
            bFlags |= LOWERCASE_OK;
         }
         /* Check numbers */
         else if ((*pPass >= '0') && (*pPass <= '9'))
         {
            bFlags |= NUMBER_OK;
         }
         
         /* " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~" */
         /* https://owasp.org/www-community/password-special-characters */
         
         /* Check symbols " !"#$%&'()*+,-./" */
         else if ((*pPass >= 0x20) && (*pPass <= 0x2F))
         {
            bFlags |= SYMBOL_OK;
         }
         /* Check symbols ":;<=>?@" */
         else if ((*pPass >= 0x3A) && (*pPass <= 0x40))
         {
            bFlags |= SYMBOL_OK;
         }
         /* Check symbols "[\]^_`" */
         else if ((*pPass >= 0x5B) && (*pPass <= 0x60))
         {
            bFlags |= SYMBOL_OK;
         }
         /* Check symbols "{|}~" */
         else if ((*pPass >= 0x7B) && (*pPass <= 0x7E))
         {
            bFlags |= SYMBOL_OK;
         }
         
         pPass++;
      }
   }
      
   /* Check password policy requirements */
   if (PASS_MASK_OK == bFlags)
   {
      rc = 0;
   }
   
   return(rc);
} /* CheckPasswordRules */

/*************************************************************************/
/*  Init                                                                 */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int Init (char *pPass)
{
   int    rc;
   size_t PassLen = strlen(pPass);

   rc = CheckPasswordRules(pPass);
   if (ELCA_OK == rc)
   {
      rc = ELCAFirstInit(pPass, PassLen);
      if (ELCA_OK == rc)
      { 
         nELCAStatus = STATUS_UNLOCKED;
      }   
   }
   else
   {
      rc = ELCA_ERROR;
   }
   
   return(rc);
} /* Init */

/*************************************************************************/
/*  Lock                                                                 */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int Lock (void)
{
   int rc = ELCA_OK;
   
   nELCAStatus    = STATUS_LOCKED;
   nCAKeyNotFound = 1;

   /* Clear key */
   memset(ELCAKey, 0x00, sizeof(ELCAKey));
   
   /* Clear PSK */
   memset(PSK, 0x00, sizeof(PSK));
   
   /* Clear Root and Inter Cert data */
   mbedtls_x509_crt_free(&RootCert.crt);
   mbedtls_x509_crt_free(&InterCert.crt);
   
   memset(&RootCert, 0x00, sizeof(RootCert));
   memset(&InterCert, 0x00, sizeof(InterCert));
   
   snprintf(RootCert.CN,  sizeof(RootCert.CN),  "The root certificate \"/elca/root.crt\" could not be found.");
   snprintf(InterCert.CN, sizeof(InterCert.CN), "The intermediate certificate \"/elca/inter.crt\" could not be found.");
   
   /* Clear key */   
   mbedtls_pk_free(&InterKey);
   
   return(rc);
} /* Lock */

/*************************************************************************/
/*  Unlock                                                               */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int Unlock (char *pPass)
{
   int                        rc;
   size_t                     PassLen = strlen(pPass);
   int                        fd;
   static mbedtls_aes_context ctx;
   static uint8_t             data[AES_DATA_BYTES_CNT];


   /* 
    * Check if the key is the correct one 
    */
   
   /* Generate the key */
   rc = ELCACreateKey(pPass, PassLen);
   if (rc != 0) GOTO_END(ELCA_ERROR);

   /* Read the key */   
   fd = _open("SD0:/elca/elca.key", _O_BINARY | _O_RDONLY);
   if (-1 == fd) GOTO_END(ELCA_ERROR);
   _read(fd, data, sizeof(data));
   _close(fd);
         
   /* Decrypt the key */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_dec(&ctx, ELCAKey, (ELCA_KEY_LEN*8));
   rc = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, 
                              (uint8_t*)data,
                              (uint8_t*)data);
   mbedtls_aes_free(&ctx);

   if (rc != 0) GOTO_END(ELCA_ERR_PASS_WRONG);
         
   /* Compare the key */
   if (memcmp(data, ELCATest, sizeof(ELCATest)) != 0) GOTO_END(ELCA_ERR_PASS_WRONG);

   /* The key is correct, unlock the ELCA now */   
   rc = ELCAUnlock();
   if (rc != 0) GOTO_END(ELCA_ERROR);
   
   LoadCAKey();
   LoadPSK();
   
   nELCAStatus = STATUS_UNLOCKED;

end:
   return(rc);
} /* Unlock */

/*************************************************************************/
/*  JSONSendError                                                        */
/*                                                                       */
/*  In    : hs, nError, pMsg                                             */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void JSONSendError (HTTPD_SESSION *hs, int nError)
{
   s_puts("{", hs->s_stream);
   
   if (0 == nError)
   {
      s_puts("\"err\":0,\"msg\":\"none\"", hs->s_stream);
   }
   else
   {
      s_printf(hs->s_stream, "\"err\":%d,\"msg\":\"error\"", nError);
   }

   s_puts("}", hs->s_stream);
   s_flush(hs->s_stream);

} /* JSONSendError */

/*************************************************************************/
/*  ssi_is_locked                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ssi_is_locked (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%d", nELCAStatus);
   s_flush(hs->s_stream);

   return(0);
} /* ssi_is_locked */

/*************************************************************************/
/*  ssi_key_error                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ssi_key_error (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%d", nCAKeyNotFound);
   s_flush(hs->s_stream);

   return(0);
} /* ssi_key_error */

/*************************************************************************/
/*  ssi_psk_error                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ssi_psk_error (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%d", nPSKNotFound);
   s_flush(hs->s_stream);

   return(0);
} /* ssi_psk_error */

/*************************************************************************/
/*  ssi_rc_xxx                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ssi_rc_cn (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.CN);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_o (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.O);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_c (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.C);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_nb (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.NB);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_na (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.NA);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_icn (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.ICN);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_io (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.IO);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_ic (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.IC);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_rc_s (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", RootCert.S);
   s_flush(hs->s_stream);

   return(0);
}

/*************************************************************************/
/*  ssi_ic_xxx                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/

static int ssi_ic_cn (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.CN);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_o (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.O);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_c (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.C);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_nb (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.NB);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_na (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.NA);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_icn (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.ICN);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_io (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.IO);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_ic (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.IC);
   s_flush(hs->s_stream);

   return(0);
}

static int ssi_ic_s (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%s", InterCert.S);
   s_flush(hs->s_stream);

   return(0);
}

/*************************************************************************/
/*  cgi_status                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_status (HTTPD_SESSION *hs)
{
   IP_WEBS_CGISendHeader(hs);

   s_puts("{", hs->s_stream);
   s_printf(hs->s_stream, "\"locked\":%d", nELCAStatus);
   s_puts("}", hs->s_stream);
   s_flush(hs->s_stream);
   
   return(0);
} /* cgi_status */

/*************************************************************************/
/*  cgi_init_elca                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_init_elca (HTTPD_SESSION *hs)
{
   int      rc;
   size_t   olen;
   json_t  JSON;   
   char   *pPass;

   OS_RES_LOCK(&Sema);
   
   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ELCA_ERROR);

   pPass = IP_JSON_GetString(&JSON, "pass");
   if (NULL == pPass) GOTO_END(ELCA_ERROR);

   rc = mbedtls_base64_decode(pPass, strlen(pPass), &olen, pPass, strlen(pPass)); /*lint !e64*/
   if (rc != 0) GOTO_END(ELCA_ERROR);
   pPass[olen] = 0;

   /* This function is only allowed if the status is STATUS_MUST_INIT. If not => ERROR */
   if (STATUS_MUST_INIT != nELCAStatus) GOTO_END(ELCA_ERR_NO_INIT);
   
   rc = Init(pPass);
   
end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_init_elca */

/*************************************************************************/
/*  cgi_lock_elca                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_lock_elca (HTTPD_SESSION *hs)
{
   int     rc;
   json_t  JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ELCA_ERROR);

   rc = Lock();
   if (rc != ELCA_OK) GOTO_END(ELCA_ERROR);
   
end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_lock_elca */

/*************************************************************************/
/*  cgi_unlock_elca                                                      */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_unlock_elca (HTTPD_SESSION *hs)
{
   int      rc;
   size_t   olen;
   json_t  JSON;   
   char   *pPass;

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ELCA_ERROR);

   pPass = IP_JSON_GetString(&JSON, "pass");
   if (NULL == pPass) GOTO_END(ELCA_ERROR);

   rc = mbedtls_base64_decode(pPass, strlen(pPass), &olen, pPass, strlen(pPass)); /*lint !e64*/
   if (rc != 0) GOTO_END(ELCA_ERROR);
   pPass[olen] = 0;
   
   /* Check for LOCK mode */
   if (STATUS_LOCKED != nELCAStatus) GOTO_END(ELCA_ERR_NO_LOCKED);

   rc = Unlock(pPass);

end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_unlock_elca */

/*************************************************************************/
/*  cgi_csr_dec                                                          */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_csr_dec (HTTPD_SESSION *hs)
{
   int      rc;
   char   *pCSR;
   json_t   JSON;   
   
   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ELCA_ERROR);

   pCSR = IP_JSON_GetString(&JSON, "csr");
   if (NULL == pCSR) GOTO_END(ELCA_ERROR);
   if (0 == *pCSR) GOTO_END(ELCA_ERROR);

   rc = CSRDecode(hs, pCSR);
   
end:  

   IP_JSON_Delete(&JSON);
   
   if (rc != ELCA_OK)
   {
      JSONSendError(hs, rc);
   }      
   
   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_csr_dec */

/*************************************************************************/
/*  cgi_crt_dec                                                          */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_crt_dec (HTTPD_SESSION *hs)
{
   int      rc;
   char   *pCRT;
   json_t   JSON;   
   
   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ELCA_ERROR);

   pCRT = IP_JSON_GetString(&JSON, "crt");
   if (NULL == pCRT) GOTO_END(ELCA_ERROR);
   if (0 == *pCRT) GOTO_END(ELCA_ERROR);

   rc = CRTDecode(hs, pCRT);
   
end:  

   IP_JSON_Delete(&JSON);
   
   if (rc != ELCA_OK)
   {
      JSONSendError(hs, rc);
   }      
   
   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_crt_dec */

/*************************************************************************/
/*  cgi_rootca                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_rootca (HTTPD_SESSION *hs)
{
   char *pChar;
   
   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeaderOctetStream(hs);
   
   if (STATUS_UNLOCKED == nELCAStatus)
   {
      /* Output public key */ 
      pChar = (char*)RootCert.raw;
      while (*pChar != 0)
      {
         s_putchar(hs->s_stream, *pChar);
         if (0x0A == *pChar)
         {
            s_flush(hs->s_stream);
         }
         pChar++;   
      }
   
      s_flush(hs->s_stream);
   }      
   
   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_rootca */

/*************************************************************************/
/*  cgi_interca                                                          */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_interca (HTTPD_SESSION *hs)
{
   char *pChar;
   
   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeaderOctetStream(hs);
   
   if (STATUS_UNLOCKED == nELCAStatus)
   {
      /* Output public key */ 
      pChar = (char*)InterCert.raw;
      while (*pChar != 0)
      {
         s_putchar(hs->s_stream, *pChar);
         if (0x0A == *pChar)
         {
            s_flush(hs->s_stream);
         }
         pChar++;   
      }
   
      s_flush(hs->s_stream);
   }      
   
   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_interca */

/*************************************************************************/
/*  cgi_devcrt                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_devcrt (HTTPD_SESSION *hs)
{
   char *arg;
   char *val;
   
   char   *pChar;
   uint32_t id = 0;

   OS_RES_LOCK(&Sema);

   /* GET Method */   
   for (arg = HttpArgParseFirst(&hs->s_req); arg; arg = HttpArgParseNext(&hs->s_req)) 
   {
      val = HttpArgValue(&hs->s_req);
      if (val) 
      {
         if (strcmp(arg, "id") == 0) 
         {
            id = strtoul(val, NULL, 10);
         }
       }
   }
   

   IP_WEBS_CGISendHeaderOctetStream(hs);
   
   if ((STATUS_UNLOCKED == nELCAStatus) && (id != 0))
   {
      /* Find device certificate */
      pChar = NULL;
      for (int x = 0; x < DEV_CRT_LIST_CNT; x++)
      {
         if (id == DevCRTList[x].id)
         {
            pChar = DevCRTList[x].crt_data;
            break;
         }
      }
      
      /* Output data if id was found */
      if (pChar != NULL)
      {
         /* Output public key */ 
         while (*pChar != 0)
         {
            s_putchar(hs->s_stream, *pChar);
            if (0x0A == *pChar)
            {
               s_flush(hs->s_stream);
            }
            pChar++;   
         }
   
         s_flush(hs->s_stream);
      }         
   }      
   
   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_devcrt */

/*************************************************************************/
/*  cgi_crtcsr                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_crtcsr (HTTPD_SESSION *hs)
{
   int         rc;
   char      *pCSR;
   json_t      JSON;   
   static char crt_data[DEV_CRT_DATA_SIZE];
   static char b64_data[2048];
   size_t      olen;
   uint32_t    id;
   
   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ELCA_ERROR);

   pCSR = IP_JSON_GetString(&JSON, "csr");
   if (NULL == pCSR) GOTO_END(ELCA_ERROR);
   if (0 == *pCSR) GOTO_END(ELCA_ERROR);
   
   /* Certificat ID */
   tal_CPURngHardwarePoll((uint8_t*)&id, sizeof(id));
   
   /* Create certificat */
   rc = CRTCreate(pCSR, crt_data, sizeof(crt_data), id, 1);
   if (ELCA_OK == rc)
   {
      s_puts("{", hs->s_stream);

      /* Device certification ID */      
      s_printf(hs->s_stream, "\"id\": %d,", id);
      
      /* Output Intermediate certificate */ 
      mbedtls_base64_encode((uint8_t*)b64_data, sizeof(b64_data), &olen, (uint8_t*)crt_data, strlen(crt_data));
      s_puts("\"cert\":\"", hs->s_stream);
      for (int x = 0; x < (int)olen; x++)
      {
         s_putchar(hs->s_stream, b64_data[x]);
      }
      s_puts("\",", hs->s_stream);

      /* Output Intermediate certificate */ 
      mbedtls_base64_encode((uint8_t*)b64_data, sizeof(b64_data), &olen, (uint8_t*)InterCert.raw, strlen(InterCert.raw));
      s_puts("\"certca\":\"", hs->s_stream);
      for (int x = 0; x < (int)olen; x++)
      {
         s_putchar(hs->s_stream, b64_data[x]);
      }
      s_puts("\"", hs->s_stream);

      s_puts("}", hs->s_stream);
      s_flush(hs->s_stream);
   }
   
end:  

   IP_JSON_Delete(&JSON);
   
   if (rc != ELCA_OK)
   {
      JSONSendError(hs, rc);
   }
   else
   {
   }      
   
   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_crtcsr */


/*
 * SSI variable list
 */
static const SSI_EXT_LIST_ENTRY SSIList[] =
{
   { "elca_is_locked",   ssi_is_locked },
   { "elca_key_error",   ssi_key_error },
   { "elca_psk_error",   ssi_psk_error },
   
   { "elca_rc_cn",       ssi_rc_cn     },
   { "elca_rc_o",        ssi_rc_o      },
   { "elca_rc_c",        ssi_rc_c      },
   { "elca_rc_nb",       ssi_rc_nb     },
   { "elca_rc_na",       ssi_rc_na     },
   { "elca_rc_icn",      ssi_rc_icn    },
   { "elca_rc_io",       ssi_rc_io     },
   { "elca_rc_ic",       ssi_rc_ic     },
   { "elca_rc_s",        ssi_rc_s      },

   { "elca_ic_cn",       ssi_ic_cn     },
   { "elca_ic_o",        ssi_ic_o      },
   { "elca_ic_c",        ssi_ic_c      },
   { "elca_ic_nb",       ssi_ic_nb     },
   { "elca_ic_na",       ssi_ic_na     },
   { "elca_ic_icn",      ssi_ic_icn    },
   { "elca_ic_io",       ssi_ic_io     },
   { "elca_ic_ic",       ssi_ic_ic     },
   { "elca_ic_s",        ssi_ic_s      },

   {NULL, NULL}
};

/*
 * CGI variable list
 */
static const CGI_LIST_ENTRY CGIList[] =
{
   { "cgi-bin/elca_status.cgi",     cgi_status        },
   { "cgi-bin/elca_init.cgi",       cgi_init_elca     },
   { "cgi-bin/elca_lock.cgi",       cgi_lock_elca     },
   { "cgi-bin/elca_unlock.cgi",     cgi_unlock_elca   },

   { "cgi-bin/elca_csr_dec.cgi",    cgi_csr_dec       },
   { "cgi-bin/elca_crt_dec.cgi",    cgi_crt_dec       },
   
   { "cgi-bin/elca_rootca.cgi",     cgi_rootca        },
   { "cgi-bin/elca_interca.cgi",    cgi_interca       },
   { "cgi-bin/elca_devcrt.cgi",     cgi_devcrt        },
   { "cgi-bin/elca_crtcsr.cgi",     cgi_crtcsr        },
   

   {NULL, NULL}
};

/*************************************************************************/
/*  HandleCRTReq                                                         */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleCRTReq (elca_msg_t *pRxMsg, elca_msg_t *pTxMsg)
{
   int                        rc = ELCA_RPC_ERROR;
   mbedtls_md_context_t       sha2_ctx;
   const mbedtls_md_info_t   *info_sha2;
   mbedtls_aes_context        ctx;
   uint8_t                    Key[32];
   
   /* Check if ELCA is unlocked */ 
   if (nELCAStatus != STATUS_UNLOCKED) GOTO_END(ELCA_RPC_ERR_LOCKED);

   /* Create AES key */
   info_sha2 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
   if (NULL == info_sha2) GOTO_END(ELCA_RPC_ERR_CRT_GEN);
   
   mbedtls_md_init(&sha2_ctx);
   rc = mbedtls_md_setup(&sha2_ctx, info_sha2, 1);
   if (rc != 0) GOTO_END(ELCA_RPC_ERR_CRT_GEN);
   
   rc = mbedtls_pkcs5_pbkdf2_hmac(&sha2_ctx, 
                                  (uint8_t*)PSK, strlen((char*)PSK), 
                                  NULL, 0,
                                  4096,
                                  sizeof(Key), Key);
   mbedtls_md_free(&sha2_ctx);
   if (rc != 0) GOTO_END(ELCA_RPC_ERR_CRT_GEN);
   
   /* Decode CSR data */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_dec(&ctx, Key, (sizeof(Key)*8));
   rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 
                              (size_t)pRxMsg->Data.cGetCRT.CSRLen,
                              pRxMsg->Data.cGetCRT.Random,
                              (uint8_t*)pRxMsg->Data.cGetCRT.CSR,
                              (uint8_t*)pRxMsg->Data.cGetCRT.CSR);
   mbedtls_aes_free(&ctx);
   memset(Key, 0x00, sizeof(Key));
   if (rc != 0) GOTO_END(-1);

   /* Get dummy random data */
   tal_CPURngHardwarePoll(pTxMsg->Data.rGetCRT.Random, ELCA_RPC_RAND_SIZE);

   /* Create the CRT */   
   rc = CRTCreate((char*)pRxMsg->Data.cGetCRT.CSR,
                  (char*)pTxMsg->Data.rGetCRT.CRT, 
                  ELCA_RPC_CRT_SIZE, 
                  0,
                  0);
   if (rc != 0) GOTO_END(ELCA_RPC_ERR_CRT_GEN);

   /* Set length of CRT */
   pTxMsg->Data.rGetCRT.CRTLen = (uint16_t)strlen((char*)pTxMsg->Data.rGetCRT.CRT);

   /* Set length of the replay data */
   pTxMsg->Header.Len = ELCA_REPLY_GET_CRT_SIZE;

   rc = ELCA_RPC_OK;
   
end:

   pTxMsg->Header.Result = rc;

} /* HandleCRTReq */

/*************************************************************************/
/*  HandleRootReq                                                        */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleRootReq (elca_msg_t *pRxMsg, elca_msg_t *pTxMsg)
{
   int    rc = ELCA_RPC_ERROR;
   size_t Len;
   
   (void)pRxMsg;

   /* Clear data first */   
   memset(pTxMsg->Data.rGetRoot.CRT, 0x00, sizeof(ELCA_RPC_CRT_SIZE));
   
   /* Check if ELCA is unlocked */ 
   if (nELCAStatus != STATUS_UNLOCKED) GOTO_END(ELCA_RPC_ERR_LOCKED);

   /* Check for available size */   
   Len = strlen(RootCert.raw) + 1;
   if (Len > ELCA_RPC_CRT_SIZE) GOTO_END(ELCA_RPC_ERR_ROOT_SIZE);
   
   /* Copy root certificate */   
   memcpy(pTxMsg->Data.rGetRoot.CRT, RootCert.raw, Len);
   pTxMsg->Header.Len = ELCA_REPLY_GET_ROOT_SIZE;

   rc = ELCA_RPC_OK;
   
end:

   pTxMsg->Header.Result = rc;

} /* HandleRootReq */

/*************************************************************************/
/*  HandleInterReq                                                       */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleInterReq (elca_msg_t *pRxMsg, elca_msg_t *pTxMsg)
{
   int    rc = ELCA_RPC_ERROR;
   size_t Len;
   
   (void)pRxMsg;

   /* Clear data first */   
   memset(pTxMsg->Data.rGetInter.CRT, 0x00, sizeof(ELCA_RPC_CRT_SIZE));
   
   /* Check if ELCA is unlocked */ 
   if (nELCAStatus != STATUS_UNLOCKED) GOTO_END(ELCA_RPC_ERR_LOCKED);

   /* Check for available size */   
   Len = strlen(InterCert.raw) + 1;
   if (Len > ELCA_RPC_CRT_SIZE) GOTO_END(ELCA_RPC_ERR_INTER_SIZE);
   
   /* Copy intermediate certificate */   
   memcpy(pTxMsg->Data.rGetInter.CRT, InterCert.raw, Len);
   pTxMsg->Header.Len = ELCA_REPLY_GET_INTER_SIZE;

   rc = ELCA_RPC_OK;
   
end:

   pTxMsg->Header.Result = rc;

} /* HandleInterReq */

/*************************************************************************/
/*  HandleRPC                                                            */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg, RxSize                                       */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleRPC (elca_msg_t *pRxMsg, elca_msg_t *pTxMsg, int RxSize)
{
   /* Copy header */
   memcpy(pTxMsg, pRxMsg, ELCA_RPC_HEADER_SIZE);
   
   /* Set default */
   pTxMsg->Header.Len    = 0;
   pTxMsg->Header.Result = ELCA_RPC_ERROR;
   
   /* Test for correct size */
   if (pRxMsg->Header.Len > (uint32_t)(RxSize - (int)ELCA_RPC_HEADER_SIZE))
   {
      /* Error, MsgLen to large */
      pTxMsg->Header.Result = ELCA_RPC_ERR_LEN;
   }
   else
   {
      switch (pRxMsg->Header.Func)
      {
         case ELCA_MSG_GET_CRT:   HandleCRTReq(pRxMsg, pTxMsg);   break;
         case ELCA_MSG_GET_ROOT:  HandleRootReq(pRxMsg, pTxMsg);  break;
         case ELCA_MSG_GET_INTER: HandleInterReq(pRxMsg, pTxMsg); break;

         default:
         {
            /* Error, invalid function */
            pTxMsg->Header.Result = ELCA_RPC_ERR_FUNC;
            break;
         }
      }
   }

} /* HandleRPC */

/*************************************************************************/
/*  ELCATask                                                             */
/*                                                                       */
/*  In    : task parameter                                               */
/*  Out   : none                                                         */
/*  Return: never                                                        */
/*************************************************************************/
static void ELCATask (void *arg)
{
   int                Err;
   int                Size;
   int                Socket;
   struct sockaddr_in Server;
   struct sockaddr_in Source;
   int                SourceLen;  
   static uint8_t     RxBuffer[2048];
   static uint8_t     TxBuffer[2048];
   elca_msg_t       *pRxMsg;
   elca_msg_t       *pTxMsg;
   
   (void)arg;

   /* Setup tx msg */   
   pTxMsg = (elca_msg_t*)TxBuffer;
   

   /* Wait that the IP interface is ready for use */
   while (0 == IP_IF_IsReady(IFACE_ANY))
   {
      OS_TimeDly(100);
   }

   /* Wait some time for the external switch */
   OS_TimeDly(DELAY_AFTER_LINK_MS);
   
   /* Create socket */
   Socket = socket(AF_INET, SOCK_DGRAM, 0);
   TAL_ASSERT(Socket != SOCKET_ERROR);
   
   /* Assign a name (port) to an unnamed socket */
   Server.sin_addr.s_addr = INADDR_ANY;
   Server.sin_port        = htons(ELCA_SERVER_PORT);
   Server.sin_family      = AF_INET;

   Err = bind(Socket, (struct sockaddr *)&Server, sizeof(Server)); /*lint !e740*/
   TAL_ASSERT(0 == Err);

   /* 
    * At this point the ServerSocket is 
    * created an can be used 
    */
    
   while(1)
   {
      SourceLen = sizeof(Source);
      Size = recvfrom(Socket, (uint8_t*)RxBuffer, sizeof(RxBuffer), 0,
                      (struct sockaddr *)&Source, (socklen_t*)&SourceLen); /*lint !e740*/

      if ((Size > 0) && (Size >= (int)ELCA_RPC_HEADER_SIZE))
      {
         pRxMsg = (elca_msg_t*)RxBuffer;
         if( (ELCA_RPC_HEADER_MAGIC_1 == pRxMsg->Header.Magic1)  && 
             (ELCA_RPC_HEADER_MAGIC_2 == pRxMsg->Header.Magic2)  && 
             (ELCA_RPC_SIZEVER        == pRxMsg->Header.SizeVer) )
         {
            HandleRPC(pRxMsg, pTxMsg, Size);

            /* Send response */               
            sendto(Socket, (const char *)pTxMsg, ELCA_RPC_HEADER_SIZE + pTxMsg->Header.Len, 0, 
                   (struct sockaddr *)&Source, sizeof(struct sockaddr)); /*lint !e740*/    
         }
      }
                      
      /*
       * No delay at end is needed here, because the recvfrom is blocking.
       */
   }      
   
} /* ELCATask */   

/*=======================================================================*/
/*  All code exported                                                    */
/*=======================================================================*/

/*************************************************************************/
/*  elca_Init                                                            */
/*                                                                       */
/*  Initialize the ELCA functionality of the web server.                 */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
void elca_Init (void)
{
   static int InitDone = 0;
   
   /*lint -save -e506 -e774 -e778*/

   /* Check the correct size of the ELCATest key */
   if( (sizeof(ELCATest) < AES_DATA_BYTES_CNT) &&
       (0 == InitDone)                         )
   { 
      /* Create semaphore */
      OS_RES_CREATE(&Sema);
   
      /* Register SSI and CGI list */
      IP_WEBS_SSIListAdd((SSI_EXT_LIST_ENTRY*)SSIList);
      IP_WEBS_CGIListAdd((CGI_LIST_ENTRY*)CGIList);

      /* Clear Root and Inter Cert data */
      memset(&RootCert, 0x00, sizeof(RootCert));
      memset(&InterCert, 0x00, sizeof(InterCert));
      
      snprintf(RootCert.CN,  sizeof(RootCert.CN),  "The root certificate \"/elca/root.crt\" could not be found.");
      snprintf(InterCert.CN, sizeof(InterCert.CN), "The intermediate certificate \"/elca/inter.crt\" could not be found.");
      
      /* Check if a ELCA is available */
      ELCACheckInit();
      
      /* Create the ELCA Server task */
      OS_TaskCreate(&TCBELCA, ELCATask, NULL, TASK_IP_ELCA_PRIORITY,
                    ELCAStack, TASK_IP_ELCA_STK_SIZE, "ELCA");
      

      InitDone = 1;
   }      

   /*lint -restore*/
   
} /* elca_Init */

/*lint -restore*/

/*** EOF ***/
