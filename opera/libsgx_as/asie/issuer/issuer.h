/*############################################################################
  # Copyright 2016 Intel Corporation
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
  ############################################################################*/
#ifndef EPID_ISSUER_SRC_CONTEXT_H_
#define EPID_ISSUER_SRC_CONTEXT_H_
/*!
 * \file
 * \brief Issuer context interface.
 */

#include <stddef.h>
#include "epid/common/errors.h"
#include "epid/common/types.h"
#include "epid/common/src/grouppubkey.h"
#include "epid/common/src/memory.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/math/src/ecgroup-internal.h"
#include "epid/common/math/src/finitefield-internal.h"
#include "epid/common/src/endian_convert.h"
#include "epid/common/src/sigrlvalid.h"

#include "../../ascommon/as_util.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct IPrivKey_ {
  GroupId gid;   ///< group ID
  FfElement* gamma;  ///< an integer between [0, p-1]
} IPrivKey_;

typedef struct IssuerCtx {
  GroupPubKey_* pub_key;       ///< group public key
  Epid2Params_* epid2_params;  ///< Intel(R) EPID 2.0 params
  IPrivKey_* ipriv_key;          ///< Member private key
  
  BitSupplier rnd_func;  ///< Pseudo random number generation function
  void* rnd_param;       ///< Pointer to user context for rnd_func
  HashAlg hash_alg;      ///< Hash algorithm to use

  IssuerNonce ni;

  PrivRl* priv_rl;
  SigRl* sig_rl;
} IssuerCtx;

typedef struct JoinRequest_ {
  EcPoint* F;  ///< an element in G1
  FfElement* c;  ///< an integer between [0, p-1]
  FfElement* s;  ///< an integer between [0, p-1]
} JoinRequest_;

EpidStatus EpidIssuerCreate(BitSupplier rnd_func, void* rnd_param, IssuerCtx** ctx);

EpidStatus EpidIssuerImport(GroupPubKey const* pub_key, IPrivKey const* ipriv_key,
                            BitSupplier rnd_func, void* rnd_param, IssuerCtx** ctx);
void EpidIssuerDelete(IssuerCtx** ctx);

EpidStatus CreateIssueKey(FiniteField* Fp, 
                          BitSupplier rnd_func, void* rnd_func_param,
                          IPrivKey_** ipriv_key);
void DeleteIssueKey(IPrivKey_** ipriv_key);

EpidStatus GenerateNonce(IssuerNonce* ni, IssuerCtx* ctx);

EpidStatus IsJoinRequestValid(GroupPubKey const* pub_key, IssuerNonce const* ni,
                              HashAlg hash_alg, JoinRequest const* join_request, bool* is_equal);

EpidStatus CertifyMembership(JoinRequest const* join_request, IssuerNonce const* ni,
                             IssuerCtx* ctx, MembershipCredential* member_cred);

EpidStatus ExportGroupPubKey(GroupPubKey* ext_pub_key, IssuerCtx const* ctx);
EpidStatus ExportIPrivKey(IPrivKey* ext_ipriv_key, IssuerCtx const* ctx);


EpidStatus RevokePriv(FpElemStr* priv, IssuerCtx* ctx);
EpidStatus RevokeSig(EpidSignature* sig, IssuerCtx* ctx);


#ifdef __cplusplus
}
#endif

#endif  // EPID_MEMBER_SRC_CONTEXT_H_
