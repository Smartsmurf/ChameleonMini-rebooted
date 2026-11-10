/*
 * MifareTagType2.h
 *
 *  Created on: 06.11.2026
 *      Author: Smartsmurf
 */

#ifndef MIFARETAGTYPE2_H_
#define MIFARETAGTYPE2_H_

#include "Application.h"
#include "ISO14443-3A.h"

#define MIFARE_ULTRALIGHT_UID_SIZE          ISO14443A_UID_SIZE_DOUBLE
#define MIFARE_ULTRALIGHT_PAGE_SIZE         4
#define MIFARE_ULTRALIGHT_PAGES             16
#define MIFARE_ULTRALIGHT_EV11_PAGES        20
#define MIFARE_ULTRALIGHT_EV12_PAGES        41
#define MIFARE_ULTRALIGHT_HEADER_SIZE       56
#define NTAG213_PAGES                       45
#define NTAG215_PAGES                       135
#define NTAG216_PAGES                       231
#define MIFARE_ULTRALIGHT_MEM_SIZE          (MIFARE_ULTRALIGHT_HEADER_SIZE + (MIFARE_ULTRALIGHT_PAGES * MIFARE_ULTRALIGHT_PAGE_SIZE))
#define MIFARE_ULTRALIGHT_EV11_MEM_SIZE     (MIFARE_ULTRALIGHT_HEADER_SIZE + (MIFARE_ULTRALIGHT_EV11_PAGES * MIFARE_ULTRALIGHT_PAGE_SIZE))
#define MIFARE_ULTRALIGHT_EV12_MEM_SIZE     (MIFARE_ULTRALIGHT_HEADER_SIZE + (MIFARE_ULTRALIGHT_EV12_PAGES * MIFARE_ULTRALIGHT_PAGE_SIZE))
#define NTAG213_MEM_SIZE                    (MIFARE_ULTRALIGHT_HEADER_SIZE + (NTAG213_PAGES * MIFARE_ULTRALIGHT_PAGE_SIZE))
#define NTAG215_MEM_SIZE                    (MIFARE_ULTRALIGHT_HEADER_SIZE + (NTAG215_PAGES * MIFARE_ULTRALIGHT_PAGE_SIZE))
#define NTAG216_MEM_SIZE                    (MIFARE_ULTRALIGHT_HEADER_SIZE + (NTAG216_PAGES * MIFARE_ULTRALIGHT_PAGE_SIZE))
#define MIFARE_ULTRALIGHT_PWD_ADDRESS       0 // In working memory
#define MIFARE_ULTRALIGHT_PWD_SIZE          4 // Bytes


void NTAG213AppInit(void);
void NTAG215AppInit(void);
void NTAG216AppInit(void);

void MifareUltralightAppInit(void);
void MifareUltralightEV11AppInit(void);
void MifareUltralightEV12AppInit(void);
void MifareUltralightAppReset(void);
void MifareTagType2AppTask(void);

uint16_t MifareUltralightAppProcess(uint8_t* Buffer, uint16_t BitCount);

void MifareUltralightGetUid(ConfigurationUidType Uid);
void MifareUltralightSetUid(ConfigurationUidType Uid);

void MifareUltralightGetAtqa(uint16_t * Atqa);
void MifareUltralightSetAtqa(uint16_t Atqa);
void MifareUltralightGetSak(uint8_t * Sak);
void MifareUltralightSetSak(uint8_t Sak);

#endif /* MIFARETAGTYPE2_H_ */
