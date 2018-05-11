/*-------------------------------------------------------------------------
 *
 * ethereum.h
 *		Headers of routines for integration with Ethereum.
 *
 * Copyright (c) 2017-2018, Postgres Professional
 *
 * Author: Alexander Kuzmenkov <a.kuzmenkov@postgrespro.ru>
 *
 * IDENTIFICATION
 *	  contrib/pg_credereum/ethereum.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ETHEREUM_H
#define ETHEREUM_H

#include <stdint.h>

#define ethCheck(cond, params...) {if(!(cond)) { elog(ERROR, "eth: " params);}}
#define ethAssert(cond) ethCheck(cond, "internal error at %s, %d", __FILE__, __LINE__)

/* A !BIG-ENDIAN! representation of a 256-bit uint used by Etherium */
typedef union {
	uint8_t i8[32];
	uint64_t i64[4];
	uint32_t i32[8];
} uint256;

uint256 makeUint256(unsigned int a);
uint32_t makeUint32(uint256 a);

char* printUint256(uint256 n);
char* printAddress(uint256 n);

uint256 sha3(uint256 v);
uint256 sha3_2(uint256 a, uint256 b);
uint256 sha3n(const char* s, int n);
uint256 sha3s(const char* s);
uint256 sha3test();
uint256 readUint256(const char *s);
uint256 readUint256n(const char *s, int n);
void readHex(const char* s, char** buf, int *bufLen);
char* printHex(void* buf, int bytes);
char* debugPrintHex(void* buf, int bytes);

#define MIN(a,b) ((a) < (b) ? a : b)
#define MAX(a,b) ((a) > (b) ? a : b)

uint256 getStorageAt(uint256 account, uint256 key);
uint256 getFirstAccount(void);


#define ETH_MAX_PARAMS 32

typedef enum {
	EPT_Uint,
	EPT_String,
	EPT_Address,
	EPT_Raw /*output raw call result for debugging purposes*/
} EthParamType;

typedef struct {
	char *signature;
	uint256 sourceAccount;
	uint256 contractAccount;
	int isConstant;

	uint32_t sigHash;
	int nParams;
	EthParamType paramTypes[ETH_MAX_PARAMS];
	char *paramValues[ETH_MAX_PARAMS];
	int nReturn;
	EthParamType returnTypes[ETH_MAX_PARAMS];
	char *returnValues[ETH_MAX_PARAMS];
	uint256 ethTxId;
} EthCallContext;

void ethParseMethodSignature(EthCallContext *);
void ethCallMethod(EthCallContext *);

typedef struct json_t json_t;
json_t* ethSendTransaction(uint256 from, uint256 to, const char* payload);
json_t* ethCall(uint256 from, uint256 to, const char* payload);
json_t* getTransactionReceipt(uint256 transactionId);
json_t* getTransaction(uint256 transactionId);
int getCurrentBlockNumber(void);
int getTxBlock(uint256 tid);
int ethWait(uint256 transactionId);

void getNonzeroBytes(uint256 account, uint256 base, uint32_t **x, int *n);
char *getString(uint256 account, uint256 base);

#endif
