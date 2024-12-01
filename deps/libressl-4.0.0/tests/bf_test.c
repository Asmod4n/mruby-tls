/*	$OpenBSD: bf_test.c,v 1.2 2022/11/07 23:04:25 joshua Exp $ */
/*
 * Copyright (c) 2022 Joshua Sing <joshua@hypera.dev>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/evp.h>
#include <openssl/blowfish.h>

#include <stdint.h>
#include <string.h>

struct bf_test {
	const int mode;
	const uint8_t key[64];
	const int key_len;
	const uint8_t iv[64];
	const int iv_len;
	const uint8_t in[64];
	const int in_len;
	const uint8_t out[64];
	const int out_len;
	const int padding;
};

static const struct bf_test bf_tests[] = {
	/*
	 * ECB - Test vectors from
	 * https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
	 */
	{
		.mode = NID_bf_ecb,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 8,
		.out = {
			0x4E, 0xF9, 0x97, 0x45, 0x61, 0x98, 0xDD, 0x78,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
		.key_len = 8,
		.in = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
		.in_len = 8,
		.out = {
			0x51, 0x86, 0x6F, 0xD5, 0xB8, 0x5E, 0xCB, 0x8A,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.in = {
			0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
		.in_len = 8,
		.out = {
			0x7D, 0x85, 0x6F, 0x9A, 0x61, 0x30, 0x63, 0xF2,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		.key_len = 8,
		.in = {
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		.in_len = 8,
		.out = {
			0x24, 0x66, 0xDD, 0x87, 0x8B, 0x96, 0x3C, 0x9D,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.key_len = 8,
		.in = {
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		.in_len = 8,
		.out = {
			0x61, 0xF9, 0xC3, 0x80, 0x22, 0x81, 0xB0, 0x96,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		.key_len = 8,
		.in = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.in_len = 8,
		.out = {
			0x7D, 0x0C, 0xC6, 0x30, 0xAF, 0xDA, 0x1E, 0xC7,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
		},
		.key_len = 8,
		.in = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.in_len = 8,
		.out = {
			0x0A, 0xCE, 0xAB, 0x0F, 0xC6, 0xA0, 0xA2, 0x8D,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57,
		},
		.key_len = 8,
		.in = {
			0x01, 0xA1, 0xD6, 0xD0, 0x39, 0x77, 0x67, 0x42,
		},
		.in_len = 8,
		.out = {
			0x59, 0xC6, 0x82, 0x45, 0xEB, 0x05, 0x28, 0x2B,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x31, 0xD9, 0x61, 0x9D, 0xC1, 0x37, 0x6E,
		},
		.key_len = 8,
		.in = {
			0x5C, 0xD5, 0x4C, 0xA8, 0x3D, 0xEF, 0x57, 0xDA,
		},
		.in_len = 8,
		.out = {
			0xB1, 0xB8, 0xCC, 0x0B, 0x25, 0x0F, 0x09, 0xA0,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x07, 0xA1, 0x13, 0x3E, 0x4A, 0x0B, 0x26, 0x86,
		},
		.key_len = 8,
		.in = {
			0x02, 0x48, 0xD4, 0x38, 0x06, 0xF6, 0x71, 0x72,
		},
		.in_len = 8,
		.out = {
			0x17, 0x30, 0xE5, 0x77, 0x8B, 0xEA, 0x1D, 0xA4,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x38, 0x49, 0x67, 0x4C, 0x26, 0x02, 0x31, 0x9E,
		},
		.key_len = 8,
		.in = {
			0x51, 0x45, 0x4B, 0x58, 0x2D, 0xDF, 0x44, 0x0A,
		},
		.in_len = 8,
		.out = {
			0xA2, 0x5E, 0x78, 0x56, 0xCF, 0x26, 0x51, 0xEB,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x04, 0xB9, 0x15, 0xBA, 0x43, 0xFE, 0xB5, 0xB6,
		},
		.key_len = 8,
		.in = {
			0x42, 0xFD, 0x44, 0x30, 0x59, 0x57, 0x7F, 0xA2,
		},
		.in_len = 8,
		.out = {
			0x35, 0x38, 0x82, 0xB1, 0x09, 0xCE, 0x8F, 0x1A,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x13, 0xB9, 0x70, 0xFD, 0x34, 0xF2, 0xCE,
		},
		.key_len = 8,
		.in = {
			0x05, 0x9B, 0x5E, 0x08, 0x51, 0xCF, 0x14, 0x3A,
		},
		.in_len = 8,
		.out = {
			0x48, 0xF4, 0xD0, 0x88, 0x4C, 0x37, 0x99, 0x18,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x70, 0xF1, 0x75, 0x46, 0x8F, 0xB5, 0xE6,
		},
		.key_len = 8,
		.in = {
			0x07, 0x56, 0xD8, 0xE0, 0x77, 0x47, 0x61, 0xD2,
		},
		.in_len = 8,
		.out = {
			0x43, 0x21, 0x93, 0xB7, 0x89, 0x51, 0xFC, 0x98,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x43, 0x29, 0x7F, 0xAD, 0x38, 0xE3, 0x73, 0xFE,
		},
		.key_len = 8,
		.in = {
			0x76, 0x25, 0x14, 0xB8, 0x29, 0xBF, 0x48, 0x6A,
		},
		.in_len = 8,
		.out = {
			0x13, 0xF0, 0x41, 0x54, 0xD6, 0x9D, 0x1A, 0xE5,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x07, 0xA7, 0x13, 0x70, 0x45, 0xDA, 0x2A, 0x16,
		},
		.key_len = 8,
		.in = {
			0x3B, 0xDD, 0x11, 0x90, 0x49, 0x37, 0x28, 0x02,
		},
		.in_len = 8,
		.out = {
			0x2E, 0xED, 0xDA, 0x93, 0xFF, 0xD3, 0x9C, 0x79,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x04, 0x68, 0x91, 0x04, 0xC2, 0xFD, 0x3B, 0x2F,
		},
		.key_len = 8,
		.in = {
			0x26, 0x95, 0x5F, 0x68, 0x35, 0xAF, 0x60, 0x9A,
		},
		.in_len = 8,
		.out = {
			0xD8, 0x87, 0xE0, 0x39, 0x3C, 0x2D, 0xA6, 0xE3,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x37, 0xD0, 0x6B, 0xB5, 0x16, 0xCB, 0x75, 0x46,
		},
		.key_len = 8,
		.in = {
			0x16, 0x4D, 0x5E, 0x40, 0x4F, 0x27, 0x52, 0x32,
		},
		.in_len = 8,
		.out = {
			0x5F, 0x99, 0xD0, 0x4F, 0x5B, 0x16, 0x39, 0x69,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x1F, 0x08, 0x26, 0x0D, 0x1A, 0xC2, 0x46, 0x5E,
		},
		.key_len = 8,
		.in = {
			0x6B, 0x05, 0x6E, 0x18, 0x75, 0x9F, 0x5C, 0xCA,
		},
		.in_len = 8,
		.out = {
			0x4A, 0x05, 0x7A, 0x3B, 0x24, 0xD3, 0x97, 0x7B,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x58, 0x40, 0x23, 0x64, 0x1A, 0xBA, 0x61, 0x76,
		},
		.key_len = 8,
		.in = {
			0x00, 0x4B, 0xD6, 0xEF, 0x09, 0x17, 0x60, 0x62,
		},
		.in_len = 8,
		.out = {
			0x45, 0x20, 0x31, 0xC1, 0xE4, 0xFA, 0xDA, 0x8E,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x02, 0x58, 0x16, 0x16, 0x46, 0x29, 0xB0, 0x07,
		},
		.key_len = 8,
		.in = {
			0x48, 0x0D, 0x39, 0x00, 0x6E, 0xE7, 0x62, 0xF2,
		},
		.in_len = 8,
		.out = {
			0x75, 0x55, 0xAE, 0x39, 0xF5, 0x9B, 0x87, 0xBD,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x49, 0x79, 0x3E, 0xBC, 0x79, 0xB3, 0x25, 0x8F,
		},
		.key_len = 8,
		.in = {
			0x43, 0x75, 0x40, 0xC8, 0x69, 0x8F, 0x3C, 0xFA,
		},
		.in_len = 8,
		.out = {
			0x53, 0xC5, 0x5F, 0x9C, 0xB4, 0x9F, 0xC0, 0x19,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x4F, 0xB0, 0x5E, 0x15, 0x15, 0xAB, 0x73, 0xA7,
		},
		.key_len = 8,
		.in = {
			0x07, 0x2D, 0x43, 0xA0, 0x77, 0x07, 0x52, 0x92,
		},
		.in_len = 8,
		.out = {
			0x7A, 0x8E, 0x7B, 0xFA, 0x93, 0x7E, 0x89, 0xA3,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x49, 0xE9, 0x5D, 0x6D, 0x4C, 0xA2, 0x29, 0xBF,
		},
		.key_len = 8,
		.in = {
			0x02, 0xFE, 0x55, 0x77, 0x81, 0x17, 0xF1, 0x2A,
		},
		.in_len = 8,
		.out = {
			0xCF, 0x9C, 0x5D, 0x7A, 0x49, 0x86, 0xAD, 0xB5,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x83, 0x10, 0xDC, 0x40, 0x9B, 0x26, 0xD6,
		},
		.key_len = 8,
		.in = {
			0x1D, 0x9D, 0x5C, 0x50, 0x18, 0xF7, 0x28, 0xC2,
		},
		.in_len = 8,
		.out = {
			0xD1, 0xAB, 0xB2, 0x90, 0x65, 0x8B, 0xC7, 0x78,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x1C, 0x58, 0x7F, 0x1C, 0x13, 0x92, 0x4F, 0xEF,
		},
		.key_len = 8,
		.in = {
			0x30, 0x55, 0x32, 0x28, 0x6D, 0x6F, 0x29, 0x5A,
		},
		.in_len = 8,
		.out = {
			0x55, 0xCB, 0x37, 0x74, 0xD1, 0x3E, 0xF2, 0x01,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		},
		.key_len = 8,
		.in = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.in_len = 8,
		.out = {
			0xFA, 0x34, 0xEC, 0x48, 0x47, 0xB2, 0x68, 0xB2,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E,
		},
		.key_len = 8,
		.in = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.in_len = 8,
		.out = {
			0xA7, 0x90, 0x79, 0x51, 0x08, 0xEA, 0x3C, 0xAE,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE,
		},
		.key_len = 8,
		.in = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.in_len = 8,
		.out = {
			0xC3, 0x9E, 0x07, 0x2D, 0x9F, 0xAC, 0x63, 0x1D,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.in = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
		.in_len = 8,
		.out = {
			0x01, 0x49, 0x33, 0xE0, 0xCD, 0xAF, 0xF6, 0xE4,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
		.key_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 8,
		.out = {
			0xF2, 0x1E, 0x9A, 0x77, 0xB7, 0x1C, 0x49, 0xBC,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		},
		.key_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 8,
		.out = {
			0x24, 0x59, 0x46, 0x88, 0x57, 0x54, 0x36, 0x9A,
		},
		.out_len = 8,
	},
	{
		.mode = NID_bf_ecb,
		.key = {
			0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		},
		.key_len = 8,
		.in = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
		.in_len = 8,
		.out = {
			0x6B, 0x5C, 0x5A, 0x9C, 0x5D, 0x9E, 0x0A, 0x5A,
		},
		.out_len = 8,
	},

	/*
	 * CBC - Test vector from
	 * https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
	 */
	{
		.mode = NID_bf_cbc,
		.key = {
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
		},
		.key_len = 16,
		.iv = {
			0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		},
		.iv_len = 8,
		.in = {
			0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
			0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
			0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
			0x66, 0x6F, 0x72, 0x20, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 32,
		.out = {
			0x6B, 0x77, 0xB4, 0xD6, 0x30, 0x06, 0xDE, 0xE6,
			0x05, 0xB1, 0x56, 0xE2, 0x74, 0x03, 0x97, 0x93,
			0x58, 0xDE, 0xB9, 0xE7, 0x15, 0x46, 0x16, 0xD9,
			0x59, 0xF1, 0x65, 0x2B, 0xD5, 0xFF, 0x92, 0xCC,
		},
		.out_len = 32,
		.padding = 0,
	},

	/* CBC (generated using https://github.com/joshuasing/libressl-test-gen) */
	{
		.mode = NID_bf_cbc,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78,
			0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cbc,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0xb9, 0x95, 0xf2, 0x4d, 0xdf, 0xe8, 0x7b, 0xf0,
			0x05, 0x3c, 0x33, 0x39, 0x43, 0x35, 0x83, 0x62,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cbc,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.in_len = 16,
		.out = {
			0x86, 0x6f, 0x5e, 0x72, 0xe5, 0x9a, 0x19, 0x51,
			0x56, 0xf3, 0x2f, 0x5e, 0x95, 0xfb, 0xd6, 0x52,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cbc,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		.in_len = 32,
		.out = {
			0xb9, 0x95, 0xf2, 0x4d, 0xdf, 0xe8, 0x7b, 0xf0,
			0x00, 0xf6, 0x2e, 0xf6, 0x6a, 0x03, 0x2d, 0x40,
			0x9c, 0xc9, 0x06, 0x31, 0x67, 0x7f, 0x6e, 0x24,
			0xeb, 0x2d, 0x3b, 0x02, 0xa3, 0x53, 0x52, 0xe9,
		},
		.out_len = 32,
	},
	{
		.mode = NID_bf_cbc,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78,
			0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61,
			0x8b, 0xa5, 0x5d, 0x18, 0x27, 0x44, 0x9c, 0xd3,
		},
		.out_len = 24,
		.padding = 1,
	},
	{
		.mode = NID_bf_cbc,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 12,
		.out = {
			0xc0, 0x1f, 0xae, 0x76, 0x86, 0x86, 0xe7, 0xb7,
			0x3b, 0x0d, 0xd9, 0x72, 0x33, 0x2b, 0x38, 0x5d,
		},
		.out_len = 16,
		.padding = 1,
	},

	/* CFB64 (generated using https://github.com/joshuasing/libressl-test-gen) */
	{
		.mode = NID_bf_cfb64,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78,
			0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cfb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0xb9, 0x95, 0xf2, 0x4d, 0xdf, 0xe8, 0x7b, 0xf0,
			0x05, 0x3c, 0x33, 0x39, 0x43, 0x35, 0x83, 0x62,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cfb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.in_len = 16,
		.out = {
			0xb9, 0x94, 0xf0, 0x4e, 0xdb, 0xed, 0x7d, 0xf7,
			0x0a, 0xf8, 0x96, 0xbf, 0x4d, 0x3c, 0x95, 0xdf,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cfb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		.in_len = 32,
		.out = {
			0x86, 0x6e, 0x5c, 0x71, 0xe1, 0x9f, 0x1f, 0x56,
			0x1f, 0x02, 0xaa, 0x8c, 0x09, 0xe0, 0x61, 0x43,
			0x91, 0x8d, 0xd2, 0x43, 0x70, 0x5d, 0xa3, 0xf1,
			0xc7, 0x96, 0x56, 0x77, 0xfc, 0x33, 0x74, 0x9e,
		},
		.out_len = 32,
	},
	{
		.mode = NID_bf_cfb64,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78,
			0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_cfb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 12,
		.out = {
			0xc0, 0x1f, 0xae, 0x76, 0x86, 0x86, 0xe7, 0xb7,
			0x05, 0xbb, 0xd4, 0x5e,
		},
		.out_len = 12,
	},

	/* OFB64 (generated using https://github.com/joshuasing/libressl-test-gen) */
	{
		.mode = NID_bf_ofb64,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78,
			0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_ofb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0xb9, 0x95, 0xf2, 0x4d, 0xdf, 0xe8, 0x7b, 0xf0,
			0x05, 0x3c, 0x33, 0x39, 0x43, 0x35, 0x83, 0x62,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_ofb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.in_len = 16,
		.out = {
			0xb9, 0x94, 0xf0, 0x4e, 0xdb, 0xed, 0x7d, 0xf7,
			0x0d, 0x35, 0x39, 0x32, 0x4f, 0x38, 0x8d, 0x6d,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_ofb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		.key_len = 16,
		.iv = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		.in_len = 32,
		.out = {
			0x86, 0x6e, 0x5c, 0x71, 0xe1, 0x9f, 0x1f, 0x56,
			0xbb, 0xcb, 0xd9, 0x35, 0x81, 0x57, 0xea, 0xb9,
			0xd7, 0x85, 0x28, 0x4a, 0xdc, 0xeb, 0x94, 0x99,
			0xf0, 0x87, 0x7c, 0x5a, 0x56, 0x60, 0xc7, 0x60,
		},
		.out_len = 32,
	},
	{
		.mode = NID_bf_ofb64,
		.key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 16,
		.out = {
			0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78,
			0xe1, 0xc0, 0x30, 0xe7, 0x4c, 0x14, 0xd2, 0x61,
		},
		.out_len = 16,
	},
	{
		.mode = NID_bf_ofb64,
		.key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		},
		.key_len = 8,
		.iv = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		.iv_len = 8,
		.in = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		.in_len = 12,
		.out = {
			0xc0, 0x1f, 0xae, 0x76, 0x86, 0x86, 0xe7, 0xb7,
			0x05, 0xbb, 0xd4, 0x5e,
		},
		.out_len = 12,
	},
};

#define N_BF_TESTS (sizeof(bf_tests) / sizeof(bf_tests[0]))

static int
bf_ecb_test(size_t test_number, const struct bf_test *bt)
{
	BF_KEY key;
	uint8_t out[8];

	if (bt->padding) {
		/* XXX - Handle padding */
		return 1;
	}

	/* Encryption */
	memset(out, 0, sizeof(out));
	BF_set_key(&key, bt->key_len, bt->key);
	BF_ecb_encrypt(bt->in, out, &key, 1);

	if (memcmp(bt->out, out, bt->out_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): encryption mismatch\n",
		    SN_bf_ecb, test_number);
		return 0;
	}

	/* Decryption */
	memset(out, 0, sizeof(out));
	BF_set_key(&key, bt->key_len, bt->key);
	BF_ecb_encrypt(bt->out, out, &key, 0);

	if (memcmp(bt->in, out, bt->in_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): decryption mismatch\n",
		    SN_bf_ecb, test_number);
		return 0;
	}

	return 1;
}

static int
bf_cbc_test(size_t test_number, const struct bf_test *bt)
{
	BF_KEY key;
	uint8_t out[512];
	uint8_t iv[64];

	if (bt->padding) {
		/* XXX - Handle padding */
		return 1;
	}

	/* Encryption */
	memset(out, 0, sizeof(out));
	memcpy(iv, bt->iv, bt->iv_len);
	BF_set_key(&key, bt->key_len, bt->key);
	BF_cbc_encrypt(bt->in, out, bt->in_len, &key, iv, 1);

	if (memcmp(bt->out, out, bt->out_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): encryption mismatch\n",
		    SN_bf_cbc, test_number);
		return 0;
	}

	/* Decryption */
	memset(out, 0, sizeof(out));
	memcpy(iv, bt->iv, bt->iv_len);
	BF_set_key(&key, bt->key_len, bt->key);
	BF_cbc_encrypt(bt->out, out, bt->out_len, &key, iv, 0);

	if (memcmp(bt->in, out, bt->in_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): decryption mismatch\n",
		    SN_bf_cbc, test_number);
		return 0;
	}

	return 1;
}

static int
bf_cfb64_test(size_t test_number, const struct bf_test *bt)
{
	BF_KEY key;
	uint8_t out[512];
	uint8_t iv[64];
	int remainder = 0;

	if (bt->padding) {
		/* XXX - Handle padding */
		return 1;
	}

	/* Encryption */
	memset(out, 0, sizeof(out));
	memcpy(iv, bt->iv, bt->iv_len);
	BF_set_key(&key, bt->key_len, bt->key);
	BF_cfb64_encrypt(bt->in, out, bt->in_len * 8, &key, iv, &remainder, 1);

	if (memcmp(bt->out, out, bt->out_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): encryption mismatch\n",
		    SN_bf_cfb64, test_number);
		return 0;
	}

	/* Decryption */
	remainder = 0;
	memset(out, 0, sizeof(out));
	memcpy(iv, bt->iv, bt->iv_len);
	BF_set_key(&key, bt->key_len, bt->key);
	BF_cfb64_encrypt(bt->out, out, bt->out_len, &key, iv, &remainder, 0);

	if (memcmp(bt->in, out, bt->in_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): decryption mismatch\n",
		    SN_bf_cfb64, test_number);
		return 0;
	}

	return 1;
}

static int
bf_ofb64_test(size_t test_number, const struct bf_test *bt)
{
	BF_KEY key;
	uint8_t out[512];
	uint8_t iv[64];
	int remainder = 0;

	if (bt->padding) {
		/* XXX - Handle padding */
		return 1;
	}

	/* Encryption */
	memset(out, 0, sizeof(out));
	memcpy(iv, bt->iv, bt->iv_len);
	BF_set_key(&key, bt->key_len, bt->key);
	BF_ofb64_encrypt(bt->in, out, bt->in_len, &key, iv, &remainder);

	if (memcmp(bt->out, out, bt->out_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): encryption mismatch\n",
		    SN_bf_ofb64, test_number);
		return 0;
	}

	/* Decryption */
	remainder = 0;
	memset(out, 0, sizeof(out));
	memcpy(iv, bt->iv, bt->iv_len);
	BF_set_key(&key, bt->key_len, bt->key);
	BF_ofb64_encrypt(bt->out, out, bt->out_len, &key, iv, &remainder);

	if (memcmp(bt->in, out, bt->in_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): decryption mismatch\n",
		    SN_bf_ofb64, test_number);
		return 0;
	}

	return 1;
}

static int
bf_evp_test(size_t test_number, const struct bf_test *bt, const char *label,
    const EVP_CIPHER *cipher)
{
	EVP_CIPHER_CTX *ctx;
	uint8_t out[512];
	int in_len, out_len, total_len;
	int i;
	int success = 0;

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_CIPHER_CTX_new failed\n",
		    label, test_number);
		goto failed;
	}

	/* EVP encryption */
	total_len = 0;
	memset(out, 0, sizeof(out));
	if (!EVP_EncryptInit(ctx, cipher, NULL, NULL)) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_EncryptInit failed\n",
		    label, test_number);
		goto failed;
	}

	if (!EVP_CIPHER_CTX_set_key_length(ctx, bt->key_len)) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP_CIPHER_CTX_set_key_length failed\n",
		    label, test_number);
		goto failed;
	}

	if (!EVP_CIPHER_CTX_set_padding(ctx, bt->padding)) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP_CIPHER_CTX_set_padding failed\n",
		    label, test_number);
		goto failed;
	}

	if (!EVP_EncryptInit(ctx, NULL, bt->key, bt->iv)) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_EncryptInit failed\n",
		    label, test_number);
		goto failed;
	}

	for (i = 0; i < bt->in_len;) {
		in_len = arc4random_uniform(bt->in_len / 2);
		if (in_len > bt->in_len - i)
			in_len = bt->in_len - i;

		if (!EVP_EncryptUpdate(ctx, out + total_len, &out_len,
		    bt->in + i, in_len)) {
			fprintf(stderr,
			    "FAIL (%s:%zu): EVP_EncryptUpdate failed\n",
			    label, test_number);
			goto failed;
		}

		i += in_len;
		total_len += out_len;
	}

	if (!EVP_EncryptFinal_ex(ctx, out + total_len, &out_len)) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_EncryptFinal_ex failed\n",
		    label, test_number);
		goto failed;
	}
	total_len += out_len;

	if (!EVP_CIPHER_CTX_reset(ctx)) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP_CIPHER_CTX_reset failed\n",
		    label, test_number);
		goto failed;
	}

	if (total_len != bt->out_len) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP encryption length mismatch "
		    "(%d != %d)\n", label, test_number, total_len, bt->out_len);
		goto failed;
	}

	if (memcmp(bt->out, out, bt->out_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): EVP encryption mismatch\n",
		    label, test_number);
		goto failed;
	}

	/* EVP decryption */
	total_len = 0;
	memset(out, 0, sizeof(out));
	if (!EVP_DecryptInit(ctx, cipher, NULL, NULL)) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_DecryptInit failed\n",
		    label, test_number);
		goto failed;
	}

	if (!EVP_CIPHER_CTX_set_key_length(ctx, bt->key_len)) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP_CIPHER_CTX_set_key_length failed\n",
		    label, test_number);
		goto failed;
	}

	if (!EVP_CIPHER_CTX_set_padding(ctx, bt->padding)) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP_CIPHER_CTX_set_padding failed\n",
		    label, test_number);
		goto failed;
	}

	if (!EVP_DecryptInit(ctx, NULL, bt->key, bt->iv)) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_DecryptInit failed\n",
		    label, test_number);
		goto failed;
	}

	for (i = 0; i < bt->out_len;) {
		in_len = arc4random_uniform(bt->out_len / 2);
		if (in_len > bt->out_len - i)
			in_len = bt->out_len - i;

		if (!EVP_DecryptUpdate(ctx, out + total_len, &out_len,
		    bt->out + i, in_len)) {
			fprintf(stderr,
			    "FAIL (%s:%zu): EVP_DecryptUpdate failed\n",
			    label, test_number);
			goto failed;
		}

		i += in_len;
		total_len += out_len;
	}

	if (!EVP_DecryptFinal_ex(ctx, out + total_len, &out_len)) {
		fprintf(stderr, "FAIL (%s:%zu): EVP_DecryptFinal_ex failed\n",
		    label, test_number);
		goto failed;
	}
	total_len += out_len;

	if (!EVP_CIPHER_CTX_reset(ctx)) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP_CIPHER_CTX_reset failed\n",
		    label, test_number);
		goto failed;
	}

	if (total_len != bt->in_len) {
		fprintf(stderr,
		    "FAIL (%s:%zu): EVP decryption length mismatch\n",
		    label, test_number);
		goto failed;
	}

	if (memcmp(bt->in, out, bt->in_len) != 0) {
		fprintf(stderr, "FAIL (%s:%zu): EVP decryption mismatch\n",
		    label, test_number);
		goto failed;
	}

	success = 1;

 failed:
	EVP_CIPHER_CTX_free(ctx);
	return success;
}

static int
bf_test(void)
{
	const struct bf_test *bt;
	const char *label;
	const EVP_CIPHER *cipher;
	size_t i;
	int failed = 1;

	for (i = 0; i < N_BF_TESTS; i++) {
		bt = &bf_tests[i];
		switch (bt->mode) {
		case NID_bf_ecb:
			label = SN_bf_ecb;
			cipher = EVP_bf_ecb();
			if (!bf_ecb_test(i, bt))
				goto failed;
			break;
		case NID_bf_cbc:
			label = SN_bf_cbc;
			cipher = EVP_bf_cbc();
			if (!bf_cbc_test(i, bt))
				goto failed;
			break;
		case NID_bf_cfb64:
			label = SN_bf_cfb64;
			cipher = EVP_bf_cfb64();
			if (!bf_cfb64_test(i, bt))
				goto failed;
			break;
		case NID_bf_ofb64:
			label = SN_bf_ofb64;
			cipher = EVP_bf_ofb();
			if (!bf_ofb64_test(i, bt))
				goto failed;
			break;
		default:
			fprintf(stderr, "FAIL: unknown mode (%d)\n",
			    bt->mode);
			goto failed;
		}

		if (!bf_evp_test(i, bt, label, cipher))
			goto failed;
	}

	failed = 0;

 failed:
	return failed;
}

int
main(int argc, char **argv)
{
	int failed = 0;

	failed |= bf_test();

	return failed;
}

