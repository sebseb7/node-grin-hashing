#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

#include "blake2.h"  
#include "portable_endian.h"    // for htole32/64
#include "int-util.h"

typedef struct siphash_keys__
{
	uint64_t k0;
	uint64_t k1;
	uint64_t k2;
	uint64_t k3;
} siphash_keys;

static void setsipkeys(const char *keybuf,siphash_keys *keys) {
	keys->k0 = htole64(((uint64_t *)keybuf)[0]);
	keys->k1 = htole64(((uint64_t *)keybuf)[1]);
	keys->k2 = htole64(((uint64_t *)keybuf)[2]);
	keys->k3 = htole64(((uint64_t *)keybuf)[3]);
}
static void setheader(const char *header, const uint32_t headerlen, siphash_keys *keys) {
	char hdrkey[32];
	blake2b((void *)hdrkey, sizeof(hdrkey), (const void *)header, headerlen, 0, 0);
	setsipkeys(hdrkey,keys);
}

// Cuck(at)oo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2019 John Tromp
#define PROOFSIZE 42
#define EDGEBITS 31
#define NEDGES ((uint32_t)1 << EDGEBITS)
#define EDGEMASK ((uint32_t)NEDGES - 1)
static uint64_t v0;
static uint64_t v1;
static uint64_t v2;
static uint64_t v3;
static uint64_t rotl(uint64_t x, uint64_t b) {
	return (x << b) | (x >> (64 - b));
}
static void sip_round() {
	v0 += v1; v2 += v3; v1 = rotl(v1,13);
	v3 = rotl(v3,16); v1 ^= v0; v3 ^= v2;
	v0 = rotl(v0,32); v2 += v1; v0 += v3;
	v1 = rotl(v1,17);   v3 = rotl(v3,21);
	v1 ^= v2; v3 ^= v0; v2 = rotl(v2,32);
}
static void hash24(const uint64_t nonce) {
	v3 ^= nonce;
	sip_round(); sip_round();
	v0 ^= nonce;
	v2 ^= 0xff;
	sip_round(); sip_round(); sip_round(); sip_round();
}
static uint64_t xor_lanes() {
	return (v0 ^ v1) ^ (v2  ^ v3);
}
uint32_t sipnode(siphash_keys *keys, uint32_t edge, uint32_t uorv) {
	v0=keys->k0;
	v1=keys->k1;
	v2=keys->k2;
	v3=keys->k3;
	hash24(2*edge + uorv);
	return xor_lanes() & EDGEMASK;
}
enum verify_code { POW_OK, POW_HEADER_LENGTH, POW_TOO_BIG, POW_TOO_SMALL, POW_NON_MATCHING, POW_BRANCH, POW_DEAD_END, POW_SHORT_CYCLE};
static int verify31(uint32_t edges[PROOFSIZE], siphash_keys *keys) {
	uint32_t uvs[2*PROOFSIZE], xor0, xor1;
	xor0 = xor1 = (PROOFSIZE/2) & 1;

	for (uint32_t n = 0; n < PROOFSIZE; n++) {
		if (edges[n] > EDGEMASK)
			return POW_TOO_BIG;
		if (n && edges[n] <= edges[n-1])
			return POW_TOO_SMALL;
		xor0 ^= uvs[2*n  ] = sipnode(keys, edges[n], 0);
		xor1 ^= uvs[2*n+1] = sipnode(keys, edges[n], 1);
	}
	if (xor0|xor1)              // optional check for obviously bad proofs
		return POW_NON_MATCHING;
	uint32_t n = 0, i = 0, j;
	do {                        // follow cycle
		for (uint32_t k = j = i; (k = (k+2) % (2*PROOFSIZE)) != i; ) {
			if (uvs[k]>>1 == uvs[i]>>1) { // find other edge endpoint matching one at i
				if (j != i)           // already found one before
					return POW_BRANCH;
				j = k;
			}
		}
		if (j == i || uvs[j] == uvs[i])
			return POW_DEAD_END;  // no matching endpoint
		i = j^1;
		n++;
	} while (i != 0);           // must cycle back to start or we would have found branch
	return n == PROOFSIZE ? POW_OK : POW_SHORT_CYCLE;
}

int verify29(uint32_t*, siphash_keys*);

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(cuckatoo31) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");

	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	setheader(input,input_len,&keys);

	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZE];
	for (uint32_t n = 0; n < PROOFSIZE; n++)
		edges[n]=ring->Get(n)->Uint32Value(Nan::GetCurrentContext()).ToChecked();;

	int retval = verify31(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(cyclehash31) {
	if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");

	Local<Array> ring = Local<Array>::Cast(info[0]);

	uint8_t hashdata[163]; // PROOFSIZE*EDGEBITS/8
	memset(hashdata, 0, 163);

	int bytepos = 0;
	int bitpos = 0;
	for(int i = 0; i < PROOFSIZE; i++){

		uint32_t node = ring->Get(i)->Uint32Value(Nan::GetCurrentContext()).ToChecked();

		for(int j = 0; j < 31; j++) {

			if((node >> j) & 1U)
				hashdata[bytepos] |= 1UL << bitpos;

			bitpos++;
			if(bitpos==8) {
				bitpos=0;bytepos++;
			}
		}
	}

	unsigned char cyclehash[32];
	blake2b((void *)cyclehash, sizeof(cyclehash), (uint8_t *)hashdata, sizeof(hashdata), 0, 0);

	unsigned char rev_cyclehash[32];
	for(int i = 0; i < 32; i++)
		rev_cyclehash[i] = cyclehash[31-i];

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)rev_cyclehash, 32).ToLocalChecked();
	info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cuckaroo29) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");
	
	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	setheader(input,input_len,&keys);
	
	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZE];
	for (uint32_t n = 0; n < PROOFSIZE; n++)
		edges[n]=ring->Get(n)->Uint32Value(Nan::GetCurrentContext()).ToChecked();;
	
	int retval = verify29(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(cyclehash29) {
	if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");
	
	Local<Array> ring = Local<Array>::Cast(info[0]);

	uint8_t hashdata[153]; // PROOFSIZE*EDGEBITS/8
	memset(hashdata, 0, 153);

	int bytepos = 0;
	int bitpos = 0;
	for(int i = 0; i < PROOFSIZE; i++){

		uint32_t node = ring->Get(i)->Uint32Value(Nan::GetCurrentContext()).ToChecked();

		for(int j = 0; j < 29; j++) {
			
			if((node >> j) & 1U)
				hashdata[bytepos] |= 1UL << bitpos;

			bitpos++;
			if(bitpos==8) {
				bitpos=0;bytepos++;
			}
		}
	}

	unsigned char cyclehash[32];
	blake2b((void *)cyclehash, sizeof(cyclehash), (uint8_t *)hashdata, sizeof(hashdata), 0, 0);
	
	unsigned char rev_cyclehash[32];
	for(int i = 0; i < 32; i++)
		rev_cyclehash[i] = cyclehash[31-i];
	
	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)rev_cyclehash, 32).ToLocalChecked();
	info.GetReturnValue().Set(returnValue);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NAN_MODULE_INIT(init) {
	Nan::Set(target, Nan::New("cuckatoo31").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cuckatoo31)).ToLocalChecked());
	Nan::Set(target, Nan::New("cyclehash31").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cyclehash31)).ToLocalChecked());
	Nan::Set(target, Nan::New("cuckaroo29").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cuckaroo29)).ToLocalChecked());
	Nan::Set(target, Nan::New("cyclehash29").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cyclehash29)).ToLocalChecked());
}

NODE_MODULE(grinhashing, init)

