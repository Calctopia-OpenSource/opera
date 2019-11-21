/*******************************************************************************
* Copyright 2014-2018 Intel Corporation
* All Rights Reserved.
*
* If this  software was obtained  under the  Intel Simplified  Software License,
* the following terms apply:
*
* The source code,  information  and material  ("Material") contained  herein is
* owned by Intel Corporation or its  suppliers or licensors,  and  title to such
* Material remains with Intel  Corporation or its  suppliers or  licensors.  The
* Material  contains  proprietary  information  of  Intel or  its suppliers  and
* licensors.  The Material is protected by  worldwide copyright  laws and treaty
* provisions.  No part  of  the  Material   may  be  used,  copied,  reproduced,
* modified, published,  uploaded, posted, transmitted,  distributed or disclosed
* in any way without Intel's prior express written permission.  No license under
* any patent,  copyright or other  intellectual property rights  in the Material
* is granted to  or  conferred  upon  you,  either   expressly,  by implication,
* inducement,  estoppel  or  otherwise.  Any  license   under such  intellectual
* property rights must be express and approved by Intel in writing.
*
* Unless otherwise agreed by Intel in writing,  you may not remove or alter this
* notice or  any  other  notice   embedded  in  Materials  by  Intel  or Intel's
* suppliers or licensors in any way.
*
*
* If this  software  was obtained  under the  Apache License,  Version  2.0 (the
* "License"), the following terms apply:
*
* You may  not use this  file except  in compliance  with  the License.  You may
* obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
*
*
* Unless  required  by   applicable  law  or  agreed  to  in  writing,  software
* distributed under the License  is distributed  on an  "AS IS"  BASIS,  WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the   License  for the   specific  language   governing   permissions  and
* limitations under the License.
*******************************************************************************/

/* 
// 
//  Purpose:
//     Cryptography Primitive.
//     Security Hash Standard
//     Constants
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"

#if defined( _IPP_DATA )

/*
// enabled hash alg IDs
*/
const IppHashAlgId cpEnabledHashAlgID[] = {
   IPP_ALG_HASH_UNKNOWN,

#if defined(_ENABLE_ALG_SHA1_)
   IPP_ALG_HASH_SHA1,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SHA256_)
   IPP_ALG_HASH_SHA256,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SHA224_)
   IPP_ALG_HASH_SHA224,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SHA512_)
   IPP_ALG_HASH_SHA512,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SHA384_)
   IPP_ALG_HASH_SHA384,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_MD5_)
   IPP_ALG_HASH_MD5,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SM3_)
   IPP_ALG_HASH_SM3,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SHA512_224_)
   IPP_ALG_HASH_SHA512_224,
#else
   IPP_ALG_HASH_UNKNOWN,
#endif

#if defined(_ENABLE_ALG_SHA512_256_)
   IPP_ALG_HASH_SHA512_256
#else
   IPP_ALG_HASH_UNKNOWN
#endif
};
////////////////////////////////////////////////////////////

/*
// hash init values
*/
const Ipp32u UnknownHash_IV[] = {
   0};

#if defined(_ENABLE_ALG_SHA1_)
const Ipp32u SHA1_IV[] = {
   0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
#endif

#if defined(_ENABLE_ALG_SHA256_)
const Ipp32u SHA256_IV[] = {
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
#endif

#if defined(_ENABLE_ALG_SHA224_)
const Ipp32u SHA224_IV[] = {
   0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
   0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4};
#endif

#if defined(_ENABLE_ALG_SHA512_)
const Ipp64u SHA512_IV[] = {
   CONST_64(0x6A09E667F3BCC908), CONST_64(0xBB67AE8584CAA73B),
   CONST_64(0x3C6EF372FE94F82B), CONST_64(0xA54FF53A5F1D36F1),
   CONST_64(0x510E527FADE682D1), CONST_64(0x9B05688C2B3E6C1F),
   CONST_64(0x1F83D9ABFB41BD6B), CONST_64(0x5BE0CD19137E2179)};
#endif

#if defined(_ENABLE_ALG_SHA384_)
const Ipp64u SHA384_IV[] = {
   CONST_64(0xCBBB9D5DC1059ED8), CONST_64(0x629A292A367CD507),
   CONST_64(0x9159015A3070DD17), CONST_64(0x152FECD8F70E5939),
   CONST_64(0x67332667FFC00B31), CONST_64(0x8EB44A8768581511),
   CONST_64(0xDB0C2E0D64F98FA7), CONST_64(0x47B5481DBEFA4FA4)};
#endif

#if defined(_ENABLE_ALG_MD5_)
const Ipp32u MD5_IV[] = {
   0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
#endif

#if defined(_ENABLE_ALG_SM3_)
const Ipp32u SM3_IV[] = {
   0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
   0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E};
#endif

#if defined(_ENABLE_ALG_SHA512_224_)
const Ipp64u SHA512_224_IV[] = {
   CONST_64(0x8C3D37C819544DA2), CONST_64(0x73E1996689DCD4D6),
   CONST_64(0x1DFAB7AE32FF9C82), CONST_64(0x679DD514582F9FCF),
   CONST_64(0x0F6D2B697BD44DA8), CONST_64(0x77E36F7304C48942),
   CONST_64(0x3F9D85A86A1D36C8), CONST_64(0x1112E6AD91D692A1)};
#endif

#if defined(_ENABLE_ALG_SHA512_256_)
const Ipp64u SHA512_256_IV[] = {
   CONST_64(0x22312194FC2BF72C), CONST_64(0x9F555FA3C84C64C2),
   CONST_64(0x2393B86B6F53B151), CONST_64(0x963877195940EABD),
   CONST_64(0x96283EE2A88EFFE3), CONST_64(0xBE5E1E2553863992),
   CONST_64(0x2B0199FC2C85B8AA), CONST_64(0x0EB72DDC81C52CA2)};
#endif

const Ipp8u* cpHashIV[] = {
   (Ipp8u*)UnknownHash_IV,

   #if defined(_ENABLE_ALG_SHA1_)
   (Ipp8u*)SHA1_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SHA256_)
   (Ipp8u*)SHA256_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SHA224_)
   (Ipp8u*)SHA224_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SHA512_)
   (Ipp8u*)SHA512_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SHA384_)
   (Ipp8u*)SHA384_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_MD5_)
   (Ipp8u*)MD5_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SM3_)
   (Ipp8u*)SM3_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SHA512_224_)
   (Ipp8u*)SHA512_224_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif

   #if defined(_ENABLE_ALG_SHA512_256_)
   (Ipp8u*)SHA512_256_IV,
   #else
   (Ipp8u*)UnknownHash_IV,
   #endif
};

////////////////////////////////////////////////////////////

/*
// additive constatns
*/
#if defined(_ENABLE_ALG_SHA1_)
__ALIGN16 const Ipp32u SHA1_cnt[] = {
   0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
};
#endif

#if defined(_ENABLE_ALG_SHA256_) || defined(_ENABLE_ALG_SHA224_)
__ALIGN16 const Ipp32u SHA256_cnt[] = {
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
   0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
   0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
   0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
   0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
   0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
   0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
   0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
   0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};
#endif

#if defined(_ENABLE_ALG_SHA512_) || defined(_ENABLE_ALG_SHA384_) || defined(_ENABLE_ALG_SHA512_224_) || defined(_ENABLE_ALG_SHA512_256_)
__ALIGN16 const Ipp64u SHA512_cnt[] = {
   CONST_64(0x428A2F98D728AE22), CONST_64(0x7137449123EF65CD), CONST_64(0xB5C0FBCFEC4D3B2F), CONST_64(0xE9B5DBA58189DBBC),
   CONST_64(0x3956C25BF348B538), CONST_64(0x59F111F1B605D019), CONST_64(0x923F82A4AF194F9B), CONST_64(0xAB1C5ED5DA6D8118),
   CONST_64(0xD807AA98A3030242), CONST_64(0x12835B0145706FBE), CONST_64(0x243185BE4EE4B28C), CONST_64(0x550C7DC3D5FFB4E2),
   CONST_64(0x72BE5D74F27B896F), CONST_64(0x80DEB1FE3B1696B1), CONST_64(0x9BDC06A725C71235), CONST_64(0xC19BF174CF692694),
   CONST_64(0xE49B69C19EF14AD2), CONST_64(0xEFBE4786384F25E3), CONST_64(0x0FC19DC68B8CD5B5), CONST_64(0x240CA1CC77AC9C65),
   CONST_64(0x2DE92C6F592B0275), CONST_64(0x4A7484AA6EA6E483), CONST_64(0x5CB0A9DCBD41FBD4), CONST_64(0x76F988DA831153B5),
   CONST_64(0x983E5152EE66DFAB), CONST_64(0xA831C66D2DB43210), CONST_64(0xB00327C898FB213F), CONST_64(0xBF597FC7BEEF0EE4),
   CONST_64(0xC6E00BF33DA88FC2), CONST_64(0xD5A79147930AA725), CONST_64(0x06CA6351E003826F), CONST_64(0x142929670A0E6E70),
   CONST_64(0x27B70A8546D22FFC), CONST_64(0x2E1B21385C26C926), CONST_64(0x4D2C6DFC5AC42AED), CONST_64(0x53380D139D95B3DF),
   CONST_64(0x650A73548BAF63DE), CONST_64(0x766A0ABB3C77B2A8), CONST_64(0x81C2C92E47EDAEE6), CONST_64(0x92722C851482353B),
   CONST_64(0xA2BFE8A14CF10364), CONST_64(0xA81A664BBC423001), CONST_64(0xC24B8B70D0F89791), CONST_64(0xC76C51A30654BE30),
   CONST_64(0xD192E819D6EF5218), CONST_64(0xD69906245565A910), CONST_64(0xF40E35855771202A), CONST_64(0x106AA07032BBD1B8),
   CONST_64(0x19A4C116B8D2D0C8), CONST_64(0x1E376C085141AB53), CONST_64(0x2748774CDF8EEB99), CONST_64(0x34B0BCB5E19B48A8),
   CONST_64(0x391C0CB3C5C95A63), CONST_64(0x4ED8AA4AE3418ACB), CONST_64(0x5B9CCA4F7763E373), CONST_64(0x682E6FF3D6B2B8A3),
   CONST_64(0x748F82EE5DEFB2FC), CONST_64(0x78A5636F43172F60), CONST_64(0x84C87814A1F0AB72), CONST_64(0x8CC702081A6439EC),
   CONST_64(0x90BEFFFA23631E28), CONST_64(0xA4506CEBDE82BDE9), CONST_64(0xBEF9A3F7B2C67915), CONST_64(0xC67178F2E372532B),
   CONST_64(0xCA273ECEEA26619C), CONST_64(0xD186B8C721C0C207), CONST_64(0xEADA7DD6CDE0EB1E), CONST_64(0xF57D4F7FEE6ED178),
   CONST_64(0x06F067AA72176FBA), CONST_64(0x0A637DC5A2C898A6), CONST_64(0x113F9804BEF90DAE), CONST_64(0x1B710B35131C471B),
   CONST_64(0x28DB77F523047D84), CONST_64(0x32CAAB7B40C72493), CONST_64(0x3C9EBE0A15C9BEBC), CONST_64(0x431D67C49C100D4C),
   CONST_64(0x4CC5D4BECB3E42B6), CONST_64(0x597F299CFC657E2A), CONST_64(0x5FCB6FAB3AD6FAEC), CONST_64(0x6C44198C4A475817)
};
#endif

#if defined(_ENABLE_ALG_MD5_)
__ALIGN16 const Ipp32u MD5_cnt[] = {
   0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
   0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
   0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
   0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,

   0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
   0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
   0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
   0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,

   0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
   0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
   0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
   0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,

   0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
   0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
   0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
   0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};
#endif

#if defined(_ENABLE_ALG_SM3_)
__ALIGN16 const Ipp32u SM3_cnt[] = {
   0x79CC4519,0xF3988A32,0xE7311465,0xCE6228CB,0x9CC45197,0x3988A32F,0x7311465E,0xE6228CBC,
   0xCC451979,0x988A32F3,0x311465E7,0x6228CBCE,0xC451979C,0x88A32F39,0x11465E73,0x228CBCE6,
   0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C,0xD8A7A879,0xB14F50F3,0x629EA1E7,0xC53D43CE,
   0x8A7A879D,0x14F50F3B,0x29EA1E76,0x53D43CEC,0xA7A879D8,0x4F50F3B1,0x9EA1E762,0x3D43CEC5,
   0x7A879D8A,0xF50F3B14,0xEA1E7629,0xD43CEC53,0xA879D8A7,0x50F3B14F,0xA1E7629E,0x43CEC53D,
   0x879D8A7A,0x0F3B14F5,0x1E7629EA,0x3CEC53D4,0x79D8A7A8,0xF3B14F50,0xE7629EA1,0xCEC53D43,
   0x9D8A7A87,0x3B14F50F,0x7629EA1E,0xEC53D43C,0xD8A7A879,0xB14F50F3,0x629EA1E7,0xC53D43CE,
   0x8A7A879D,0x14F50F3B,0x29EA1E76,0x53D43CEC,0xA7A879D8,0x4F50F3B1,0x9EA1E762,0x3D43CEC5
};
#endif

/*
// hash alg default processing opt argument
*/
const void* cpHashProcFuncOpt[] = {
   NULL,

   #if defined(_ENABLE_ALG_SHA1_)
   SHA1_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA256_)
   SHA256_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA224_)
   SHA256_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA512_)
   SHA512_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA384_)
   SHA512_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_MD5_)
   MD5_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SM3_)
   SM3_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA512_224_)
   SHA512_cnt,
   #else
   NULL,
   #endif

   #if defined(_ENABLE_ALG_SHA512_256_)
   SHA512_cnt,
   #else
   NULL,
   #endif
};
////////////////////////////////////////////////////////////

/* hash alg attributes */
const cpHashAttr cpHashAlgAttr[] = {
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},                            /* unknown */

#if defined(_ENABLE_ALG_SHA1_)     /* sha1 / unknown */
   {IPP_SHA1_DIGEST_BITSIZE/8, IPP_SHA1_DIGEST_BITSIZE/8,    MBS_SHA1,   sizeof(Ipp64u), {CONST_64(0x2000000000000000-1),CONST_64(0)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SHA256_)   /* sha256 / unknown */
   {IPP_SHA256_DIGEST_BITSIZE/8,IPP_SHA256_DIGEST_BITSIZE/8, MBS_SHA256, sizeof(Ipp64u), {CONST_64(0x2000000000000000-1),CONST_64(0)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SHA224_)   /* sha224 / unknown */
   {IPP_SHA256_DIGEST_BITSIZE/8,IPP_SHA224_DIGEST_BITSIZE/8, MBS_SHA224, sizeof(Ipp64u), {CONST_64(0x2000000000000000-1),CONST_64(0)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SHA512_)   /* sha512 / unknown */
   {IPP_SHA512_DIGEST_BITSIZE/8,IPP_SHA512_DIGEST_BITSIZE/8, MBS_SHA512, sizeof(Ipp64u)*2, {CONST_64(0xFFFFFFFFFFFFFFFF),CONST_64(0x2000000000000000-1)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SHA384_)   /* sha384 / unknown */
   {IPP_SHA512_DIGEST_BITSIZE/8,IPP_SHA384_DIGEST_BITSIZE/8, MBS_SHA384, sizeof(Ipp64u)*2, {CONST_64(0xFFFFFFFFFFFFFFFF),CONST_64(0x2000000000000000-1)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_MD5_)   /* md5 / unknown */
   {IPP_MD5_DIGEST_BITSIZE/8,IPP_MD5_DIGEST_BITSIZE/8, MBS_MD5, sizeof(Ipp64u), {CONST_64(0x2000000000000000-1),CONST_64(0)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SM3_)   /* sm3 / unknown */
   {IPP_SM3_DIGEST_BITSIZE/8,IPP_SM3_DIGEST_BITSIZE/8, MBS_SM3, sizeof(Ipp64u), {CONST_64(0x2000000000000000-1),CONST_64(0)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SHA512_224_)   /* sha512/224 / unknown */
   {IPP_SHA512_DIGEST_BITSIZE/8,IPP_SHA512_224_DIGEST_BITSIZE/8, MBS_SHA512, sizeof(Ipp64u)*2, {CONST_64(0xFFFFFFFFFFFFFFFF),CONST_64(0x2000000000000000-1)}},
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}},
#endif

#if defined(_ENABLE_ALG_SHA512_256_)   /* sha512/256 / unknown */
   {IPP_SHA512_DIGEST_BITSIZE/8,IPP_SHA512_256_DIGEST_BITSIZE/8, MBS_SHA512, sizeof(Ipp64u)*2, {CONST_64(0xFFFFFFFFFFFFFFFF),CONST_64(0x2000000000000000-1)}}
#else
   {0, 0, 0, 0, {CONST_64(0),CONST_64(0)}}
#endif
};

#endif /* _IPP_DATA */
