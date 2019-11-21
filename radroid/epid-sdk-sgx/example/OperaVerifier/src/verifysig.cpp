/*############################################################################
  # Copyright 2016-2018 Intel Corporation
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

/*!
 * \file
 * \brief Signature verification implementation.
 */

extern "C" {
#include "src/verifysig.h"
#include <stdlib.h>
#include <string.h>
#include "epid/verifier/api.h"
#include "epid/common/stdtypes.h"
}

/*
 *  Verifies EpidSignature of given GVCert/ASQuote/Priv_Rl/Sig_Rl combination.
 *  Returns EpidStatus message
 */
int Verify(uint8_t const* p_gvcert, uint8_t *p_asquote, uint8_t *p_srl, int sig_rl_size, uint8_t *p_prl, int priv_rl_size) {

  //Declare Status and Verifier Variables
  VerifierCtx* ctx = NULL;
	EpidStatus result = kEpidErr;
  PrivRl *g_priv_rl = NULL;       
  SigRl *g_sig_rl = NULL;
	
  //Cast Incoming Byte Arrays to Proper Object Type
	GroupVerifCert *gvc = const_cast<GroupVerifCert*>(reinterpret_cast<GroupVerifCert const*>(p_gvcert));	   
	PrivRl *priv_rl = const_cast<PrivRl*>(reinterpret_cast<PrivRl const*>(p_prl));		    
	SigRl *sig_rl = const_cast<SigRl*>(reinterpret_cast<SigRl const*>(p_srl));		    
	ASQuote *as_quote = const_cast<ASQuote*>(reinterpret_cast<ASQuote const*>(p_asquote));                   
	EpidSignature *sig = reinterpret_cast<EpidSignature *>(as_quote->signature);	     
	
  //Create Epid Verifier		
	result = EpidVerifierCreate(&gvc->pub_key,NULL, &ctx);

	if (result != kEpidNoErr) {
    return 1;
  }

  //Verifer Configuration
  if (EpidVerifierSetHashAlg(ctx, kSha256) != kEpidNoErr) {    
    return 2;
  }
  
	//Set Verifier Priv_rl
  g_priv_rl = (PrivRl*)malloc(priv_rl_size);

  if(g_priv_rl == NULL){
    return 3;
  }
  memcpy(g_priv_rl, priv_rl, priv_rl_size);

  if (EpidVerifierSetPrivRl(ctx, g_priv_rl, priv_rl_size) != kEpidNoErr) {
    return 4;
  }
	
  //Set Verifier Sig_rl
  g_sig_rl = (SigRl*)malloc(sig_rl_size);
   if(g_sig_rl == NULL){
    return 5;
  }
  memcpy(g_sig_rl, sig_rl, sig_rl_size);

  if (EpidVerifierSetSigRl(ctx, g_sig_rl, sig_rl_size) != kEpidNoErr) {
    return 6;
  }

  //Run Configure Epid Verifier
  if (EpidVerify(ctx, sig, as_quote->signature_len, as_quote, sizeof(ASQuote)) != kEpidNoErr) {
    return 7;
  }

  //Return Success Code
  return 0;
}
