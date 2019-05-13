#include "issuer.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

#define OCTSTR32_LOAD(oct, u32)      \
    do {                              \
      oct.data[0] = (unsigned char)((((uint32_t)(u32)) & 0xFF000000) >> 24);   \
      oct.data[1] = (unsigned char)((((uint32_t)(u32)) & 0xFF0000) >> 16);   \
      oct.data[2] = (unsigned char)((((uint32_t)(u32)) & 0xFF00) >> 8);   \
      oct.data[3] = (unsigned char)((((uint32_t)(u32)) & 0xFF));   \
    } while(0);


EpidStatus CreateIssueKey(FiniteField* Fp, 
                          BitSupplier rnd_func, void* rnd_func_param,
                          IPrivKey_** ipriv_key) {
  EpidStatus result = kEpidErr;
  IPrivKey_* ipriv_key_ = NULL;

  // check parameters
  if (!Fp || !ipriv_key) return kEpidBadArgErr;

  do {
    ipriv_key_ = SAFE_ALLOC(sizeof(IPrivKey_))
    if (!ipriv_key_) {
      result = kEpidMemAllocErr;
      break;
    }

    result = NewFfElement(Fp, &ipriv_key_->gamma);
    BREAK_ON_EPID_ERROR(result);
    static const BigNumStr one = {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
    result = FfGetRandom(Fp, &one, rnd_func, rnd_func_param, ipriv_key_->gamma);
    BREAK_ON_EPID_ERROR(result);

    rnd_func((unsigned int *)&ipriv_key_->gid, sizeof(ipriv_key_->gid) * 8, NULL);

    *ipriv_key = ipriv_key_;
    result = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != result) {
    DeleteIssueKey(&ipriv_key_);
  }

  return (result);
}

void DeleteIssueKey(IPrivKey_** ipriv_key) {
  if (ipriv_key) {
    if (*ipriv_key) {
      DeleteFfElement(&((*ipriv_key)->gamma));
    }
    SAFE_FREE(*ipriv_key);
  }
}

EpidStatus GenerateGroupPubKey(Epid2Params_* epid2_params, IPrivKey_* ipriv_key,
                             BitSupplier rnd_func, void* rnd_func_param,
                             GroupPubKey_** pub_key) {
  EpidStatus result = kEpidErr;
  GroupPubKey_* pubkey = NULL;
  if (!epid2_params || !ipriv_key || !rnd_func || !pub_key) {
    return kEpidBadArgErr;
  }

  if (!rnd_func_param) {};

  EcGroup* G1 = epid2_params->G1;
  EcGroup* G2 = epid2_params->G2;
  FiniteField* Fp = epid2_params->Fp;
  EcPoint* g2 = epid2_params->g2;

  do {
    pubkey = SAFE_ALLOC(sizeof(GroupPubKey_));
    if (!pubkey) {
      result = kEpidMemAllocErr;
      break;
    }
    result = NewEcPoint(G1, &pubkey->h1);
    BREAK_ON_EPID_ERROR(result);
    result =
        EcGetRandom(G1, rnd_func, &rnd_func, pubkey->h1);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(G1, &pubkey->h2);
    BREAK_ON_EPID_ERROR(result);
    result =
        EcGetRandom(G1, rnd_func, &rnd_func, pubkey->h2);
    BREAK_ON_EPID_ERROR(result);

    result = NewEcPoint(G2, &pubkey->w);
    BREAK_ON_EPID_ERROR(result);
    BigNumStr gamma_str = {0};
    result = WriteFfElement(Fp, ipriv_key->gamma, &gamma_str, sizeof(gamma_str));
    BREAK_ON_EPID_ERROR(result);
    result = EcExp(G2, g2, &gamma_str, pubkey->w);
    BREAK_ON_EPID_ERROR(result);

    pubkey->gid = ipriv_key->gid;

    *pub_key = pubkey;
    result = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != result && pubkey) {
    DeleteEcPoint(&pubkey->w);
    DeleteEcPoint(&pubkey->h2);
    DeleteEcPoint(&pubkey->h1);
    SAFE_FREE(pubkey);
  }
  return result;
}

EpidStatus ExportGroupPubKey(GroupPubKey* ext_pub_key, IssuerCtx const* ctx) {
  EpidStatus result = kEpidErr;
  if (!ext_pub_key || !ctx) {
    return kEpidBadArgErr;
  }

  GroupPubKey_* pubkey = ctx->pub_key;
  EcGroup* G1 = ctx->epid2_params->G1;
  EcGroup* G2 = ctx->epid2_params->G2;

  do {
    result = WriteEcPoint(G1, pubkey->h1, &ext_pub_key->h1, sizeof(ext_pub_key->h1));
    BREAK_ON_EPID_ERROR(result);
    result = WriteEcPoint(G1, pubkey->h2, &ext_pub_key->h2, sizeof(ext_pub_key->h2));
    BREAK_ON_EPID_ERROR(result);
    result = WriteEcPoint(G2, pubkey->w, &ext_pub_key->w, sizeof(ext_pub_key->w));
    BREAK_ON_EPID_ERROR(result);
    ext_pub_key->gid = pubkey->gid;
    result = kEpidNoErr;
  } while (0);
  return result;
}

EpidStatus ImportGroupPubKey(GroupPubKey const* ext_pub_key, IssuerCtx* ctx) {
  EpidStatus result = kEpidErr;
  GroupPubKey_* pubkey = NULL;
  if (!ext_pub_key || !ctx) {
    return kEpidBadArgErr;
  }

  EcGroup* G1 = ctx->epid2_params->G1;
  EcGroup* G2 = ctx->epid2_params->G2;

  do {
    pubkey = SAFE_ALLOC(sizeof(GroupPubKey_));
    if (!pubkey) {
      result = kEpidMemAllocErr;
      break;
    }
    result = NewEcPoint(G1, &pubkey->h1);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(G1, &pubkey->h2);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(G2, &pubkey->w);
    BREAK_ON_EPID_ERROR(result);

    result = ReadEcPoint(G1, &ext_pub_key->h1, sizeof(G1ElemStr), pubkey->h1);
    BREAK_ON_EPID_ERROR(result);
    result = ReadEcPoint(G1, &ext_pub_key->h2, sizeof(G1ElemStr), pubkey->h2);
    BREAK_ON_EPID_ERROR(result);
    result = ReadEcPoint(G2, &ext_pub_key->w, sizeof(G2ElemStr), pubkey->w);
    BREAK_ON_EPID_ERROR(result);

    pubkey->gid = ext_pub_key->gid;

    ctx->pub_key = pubkey;
    result = kEpidNoErr;
  } while (0);
  if (kEpidNoErr != result && pubkey) {
    DeleteEcPoint(&pubkey->w);
    DeleteEcPoint(&pubkey->h2);
    DeleteEcPoint(&pubkey->h1);
    SAFE_FREE(pubkey);
  }
  return result;
}

EpidStatus ExportIPrivKey(IPrivKey* ext_ipriv_key, IssuerCtx const* ctx) {
  EpidStatus result = kEpidErr;
  if (!ext_ipriv_key || !ctx) {
    return kEpidBadArgErr;
  }

  IPrivKey_* ipriv_key = ctx->ipriv_key;
  FiniteField* Fp = ctx->epid2_params->Fp;

  do {
    result = WriteFfElement(Fp, ipriv_key->gamma, &ext_ipriv_key->gamma, sizeof(ext_ipriv_key->gamma));
    BREAK_ON_EPID_ERROR(result);
    ext_ipriv_key->gid = ipriv_key->gid;
    result = kEpidNoErr;
  } while (0);
  return result;
}

EpidStatus ImportIPrivKey(IPrivKey const* ext_ipriv_key, IssuerCtx* ctx) {
  EpidStatus result = kEpidErr;
  IPrivKey_* ipriv_key_ = NULL;

  // check parameters
  if (!ext_ipriv_key || !ctx) return kEpidBadArgErr;


  FiniteField* Fp = ctx->epid2_params->Fp;

  do {
    ipriv_key_ = SAFE_ALLOC(sizeof(IPrivKey_))
    if (!ipriv_key_) {
      result = kEpidMemAllocErr;
      break;
    }

    result = NewFfElement(Fp, &ipriv_key_->gamma);
    BREAK_ON_EPID_ERROR(result);
    result = ReadFfElement(Fp, &ext_ipriv_key->gamma, sizeof(FpElemStr), ipriv_key_->gamma);
    BREAK_ON_EPID_ERROR(result);
    ipriv_key_->gid = ext_ipriv_key->gid;

    ctx->ipriv_key = ipriv_key_;
    result = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != result) {
    DeleteIssueKey(&ipriv_key_);
  }

  return (result);
}

EpidStatus EpidIssuerCreate(BitSupplier rnd_func, void* rnd_param, IssuerCtx** ctx) {
  EpidStatus result = kEpidErr;
  IssuerCtx* issuer_ctx = NULL;

  if (!rnd_func || !ctx) {
    return kEpidBadArgErr;
  }

  // Allocate memory for IssuerCtx
  issuer_ctx = SAFE_ALLOC(sizeof(IssuerCtx))
  if (!issuer_ctx) {
    return kEpidMemAllocErr;
  }

  issuer_ctx->priv_rl = SAFE_ALLOC(sizeof(PrivRl) - sizeof(FpElemStr));
  if (!issuer_ctx->priv_rl) {
    SAFE_FREE(issuer_ctx);
    return kEpidMemAllocErr;
  }

  issuer_ctx->sig_rl = SAFE_ALLOC(sizeof(SigRl) - sizeof(SigRlEntry));
  if (!issuer_ctx->sig_rl) {
    SAFE_FREE(issuer_ctx->priv_rl);
    SAFE_FREE(issuer_ctx);
    return kEpidMemAllocErr;
  }

  do {
    issuer_ctx->hash_alg = kSha256;
    // Internal representation of Epid2Params
    result = CreateEpid2Params(&issuer_ctx->epid2_params);
    BREAK_ON_EPID_ERROR(result);
    // Internal representation of Issuer Issue Key
    result = CreateIssueKey(issuer_ctx->epid2_params->Fp, rnd_func,
                            rnd_param, &issuer_ctx->ipriv_key);
    BREAK_ON_EPID_ERROR(result);

    // Internal representation of Group Pub Key
    result =
        GenerateGroupPubKey(issuer_ctx->epid2_params, issuer_ctx->ipriv_key,
                          rnd_func, rnd_param, &issuer_ctx->pub_key);
    BREAK_ON_EPID_ERROR(result);

    issuer_ctx->rnd_func = rnd_func;
    issuer_ctx->rnd_param = rnd_param;

    OctStr32 octstr32_0 = {{0x00, 0x00, 0x00, 0x00}};
    issuer_ctx->priv_rl->gid = issuer_ctx->ipriv_key->gid;
    issuer_ctx->priv_rl->version = octstr32_0;
    issuer_ctx->priv_rl->n1 = octstr32_0;
    
    issuer_ctx->sig_rl->gid = issuer_ctx->ipriv_key->gid;
    issuer_ctx->sig_rl->version = octstr32_0;
    issuer_ctx->sig_rl->n2 = octstr32_0;

    *ctx = issuer_ctx;
    result = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != result) {
    EpidIssuerDelete(&issuer_ctx);
  }

  return result;
}

// WARNING: priv_rl and sig_rl should be imported separately
EpidStatus EpidIssuerImport(GroupPubKey const* pub_key, IPrivKey const* ipriv_key,
                            BitSupplier rnd_func, void* rnd_param, IssuerCtx** ctx) {
  EpidStatus result = kEpidErr;
  IssuerCtx* issuer_ctx = NULL;

  if (!rnd_func || !ctx) {
    return kEpidBadArgErr;
  }

  // Allocate memory for IssuerCtx
  issuer_ctx = SAFE_ALLOC(sizeof(IssuerCtx))
  if (!issuer_ctx) {
    return kEpidMemAllocErr;
  }

  do {
    issuer_ctx->hash_alg = kSha256;
    // Internal representation of Epid2Params
    result = CreateEpid2Params(&issuer_ctx->epid2_params);
    BREAK_ON_EPID_ERROR(result);
    // Internal representation of Issuer Issue Key
    result = ImportIPrivKey(ipriv_key, issuer_ctx);
    BREAK_ON_EPID_ERROR(result);

    // Internal representation of Group Pub Key
    result = ImportGroupPubKey(pub_key, issuer_ctx);
    BREAK_ON_EPID_ERROR(result);

    issuer_ctx->rnd_func = rnd_func;
    issuer_ctx->rnd_param = rnd_param;

    *ctx = issuer_ctx;
    result = kEpidNoErr;
  } while (0);

  if (kEpidNoErr != result) {
    EpidIssuerDelete(&issuer_ctx);
  }

  return (kEpidNoErr);
}

void EpidIssuerDelete(IssuerCtx** ctx) {
  if (ctx && *ctx) {
    DeleteGroupPubKey(&(*ctx)->pub_key);
    DeleteEpid2Params(&(*ctx)->epid2_params);
    DeleteIssueKey(&(*ctx)->ipriv_key);
    SAFE_FREE((*ctx)->priv_rl);
    SAFE_FREE((*ctx)->sig_rl);
    SAFE_FREE(*ctx);
    *ctx = NULL;
  }
}

EpidStatus GenerateNonce(IssuerNonce* ni, IssuerCtx* ctx) {
  EpidStatus result = kEpidNoErr;
  if(0 != ctx->rnd_func((unsigned int *)&ctx->ni, sizeof(IssuerNonce) * 8, NULL)) {
    result = kEpidErr;
  }
  memcpy_S(ni, sizeof(IssuerNonce), &ctx->ni, sizeof(IssuerNonce));
  return result;
}

typedef struct JoinPCommitValues {
  BigNumStr p;     ///< Intel(R) EPID 2.0 parameter p
  G1ElemStr g1;    ///< Intel(R) EPID 2.0 parameter g1
  G2ElemStr g2;    ///< Intel(R) EPID 2.0 parameter g2
  G1ElemStr h1;    ///< Group public key value h1
  G1ElemStr h2;    ///< Group public key value h2
  G2ElemStr w;     ///< Group public key value w
  G1ElemStr F;     ///< Variable F computed in algorithm
  G1ElemStr R;     ///< Variable R computed in algorithm
  IssuerNonce NI;  ///< Nonce
} JoinPCommitValues;

EpidStatus IsJoinRequestValid(GroupPubKey const* pub_key, IssuerNonce const* ni,
                              HashAlg hash_alg, JoinRequest const* join_request, bool* is_valid) {
  EpidStatus result;
  BigNumStr cn_str;
  JoinPCommitValues commit_values;
  Epid2Params_* params = NULL;
  FfElement* c_el = NULL;
  FfElement* cn_el = NULL;
  EcPoint* f_pt = NULL;
  EcPoint* r_pt = NULL;
  EcPoint* h1_pt = NULL;

  if (!pub_key || !ni || !join_request) {
    return kEpidBadArgErr;
  }
  if (kSha256 != hash_alg && kSha384 != hash_alg && kSha512 != hash_alg) {
    return kEpidBadArgErr;
  }

  do {
    result = CreateEpid2Params(&params);
    BREAK_ON_EPID_ERROR(result);
    if (!params->Fp || !params->G1) {
      result = kEpidBadArgErr;
      break;
    }
    result = NewFfElement(params->Fp, &c_el);
    BREAK_ON_EPID_ERROR(result);
    result = NewFfElement(params->Fp, &cn_el);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(params->G1, &f_pt);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(params->G1, &h1_pt);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(params->G1, &r_pt);
    BREAK_ON_EPID_ERROR(result);

    result = ReadEcPoint(params->G1, (uint8_t*)&join_request->F, sizeof(join_request->F), f_pt);
    BREAK_ON_EPID_ERROR(result);
    result = ReadEcPoint(params->G1, (uint8_t*)&pub_key->h1, sizeof(pub_key->h1), h1_pt);
    BREAK_ON_EPID_ERROR(result);
    result = ReadFfElement(params->Fp, (uint8_t*)&join_request->c, sizeof(join_request->c), c_el);
    BREAK_ON_EPID_ERROR(result);

    result = FfNeg(params->Fp, c_el, cn_el);
    BREAK_ON_EPID_ERROR(result);
    result = WriteFfElement(params->Fp, cn_el, (uint8_t*)&cn_str, sizeof(cn_str));
    BREAK_ON_EPID_ERROR(result);

    result = EcExp(params->G1, f_pt, (BigNumStr const*)&cn_str, f_pt);
    BREAK_ON_EPID_ERROR(result);

    result = EcExp(params->G1, h1_pt, (BigNumStr const*)&join_request->s, r_pt);
    BREAK_ON_EPID_ERROR(result);

    result = EcMul(params->G1, f_pt, r_pt, r_pt);
    BREAK_ON_EPID_ERROR(result);

    // Computes c = Fp.hash(p || g1 || g2 || h1 || h2 || w ||
    // F || R || NI). Refer to Section 7.1 for hash operation over a prime
    // field.
    result = WriteBigNum(params->p, sizeof(commit_values.p),
                      (uint8_t*)&commit_values.p);
    BREAK_ON_EPID_ERROR(result);
    result = WriteEcPoint(params->G1, params->g1, (uint8_t*)&commit_values.g1,
                       sizeof(commit_values.g1));
    BREAK_ON_EPID_ERROR(result);
    result = WriteEcPoint(params->G2, params->g2, (uint8_t*)&commit_values.g2,
                       sizeof(commit_values.g2));
    BREAK_ON_EPID_ERROR(result);
    commit_values.h1 = pub_key->h1;
    commit_values.h2 = pub_key->h2;
    commit_values.w = pub_key->w;
    commit_values.F = join_request->F;
    result = WriteEcPoint(params->G1, r_pt, (uint8_t*)&commit_values.R,
                       sizeof(commit_values.R));
    BREAK_ON_EPID_ERROR(result);
    commit_values.NI = *ni;
    result = FfHash(params->Fp, (uint8_t*)&commit_values, sizeof(commit_values),
                 hash_alg, cn_el);
    BREAK_ON_EPID_ERROR(result);

    bool is_equal;
    result = FfIsEqual(params->Fp, cn_el, c_el, &is_equal);
    BREAK_ON_EPID_ERROR(result);
    *is_valid = is_equal;
    result = kEpidNoErr;
  } while (0);
  DeleteEcPoint(&h1_pt);
  DeleteEcPoint(&r_pt);
  DeleteEcPoint(&f_pt);
  DeleteFfElement(&cn_el);
  DeleteFfElement(&c_el);
  DeleteEpid2Params(&params);
  return result;
}

EpidStatus CertifyMembership(JoinRequest const* join_request, IssuerNonce const* ni,
                             IssuerCtx* ctx, MembershipCredential* member_cred) {
  EpidStatus result = kEpidNoErr;

  if (!join_request || !ni || !ctx || !member_cred) {
    return kEpidBadArgErr;
  }

  EcGroup* G1 = ctx->epid2_params->G1;
  FiniteField* Fp = ctx->epid2_params->Fp;

  EcPoint* F_pt = NULL;
  EcPoint* A_pt = NULL;
  FfElement* x_el = NULL;

  do {
    GroupPubKey pub_key;
    ExportGroupPubKey(&pub_key, ctx);
    bool is_valid;
    result = IsJoinRequestValid(&pub_key, &ctx->ni, ctx->hash_alg, join_request, &is_valid);
    BREAK_ON_EPID_ERROR(result);
    // if (!is_valid) {
    //   result = kEpidNotImpl;
    //   break;
    // }

    result = NewEcPoint(G1, &F_pt);
    BREAK_ON_EPID_ERROR(result);
    result = NewEcPoint(G1, &A_pt);
    BREAK_ON_EPID_ERROR(result);
    result = NewFfElement(Fp, &x_el);
    BREAK_ON_EPID_ERROR(result);

    result = ReadEcPoint(G1, &join_request->F, sizeof(join_request->F), F_pt);
    BREAK_ON_EPID_ERROR(result);


    member_cred->gid = ctx->ipriv_key->gid;

    static const BigNumStr one = {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
    result = FfGetRandom(Fp, &one, ctx->rnd_func, ctx->rnd_param, x_el);
    BREAK_ON_EPID_ERROR(result);
    result = WriteFfElement(Fp, x_el, &member_cred->x, sizeof(member_cred->x));
    BREAK_ON_EPID_ERROR(result);

    result = FfAdd(Fp, x_el, ctx->ipriv_key->gamma, x_el);
    BREAK_ON_EPID_ERROR(result);
    result = FfInv(Fp, x_el, x_el);
    BREAK_ON_EPID_ERROR(result);

    BigNumStr x_str = {0};
    result = WriteFfElement(Fp, x_el, &x_str, sizeof(x_str));
    BREAK_ON_EPID_ERROR(result);

    result = EcMul(G1, F_pt, ctx->epid2_params->g1, A_pt);
    BREAK_ON_EPID_ERROR(result);
    result = EcExp(G1, A_pt, &x_str, A_pt);
    BREAK_ON_EPID_ERROR(result);
    result = WriteEcPoint(G1, A_pt, &member_cred->A, sizeof(member_cred->A));
    BREAK_ON_EPID_ERROR(result);

  } while(0);
  DeleteEcPoint(&F_pt);
  DeleteEcPoint(&A_pt);
  DeleteFfElement(&x_el);
  return result;
}


uint32_t GetPrivRlSize(PrivRl* priv_rl) {
  return (uint32_t)(sizeof(PrivRl) - sizeof(FpElemStr) + (priv_rl? ntohl(priv_rl->n1) : 0) * sizeof(FpElemStr));
}

uint32_t GetSigRlSize(SigRl* sig_rl) {
  return (uint32_t)(sizeof(SigRl) - sizeof(SigRlEntry) + (sig_rl? ntohl(sig_rl->n2) : 0) * sizeof(SigRlEntry));
}

EpidStatus RevokePriv(FpElemStr* priv, IssuerCtx* ctx) {
  EpidStatus result = kEpidNoErr;

  do {
    if (!priv || !ctx) {
      result = kEpidBadArgErr;
      break;
    }
    PrivRl *new_ptr = realloc(ctx->priv_rl, GetPrivRlSize(ctx->priv_rl) + sizeof(FpElemStr));
    if (!new_ptr) {
      result = kEpidMemAllocErr;
      break;
    }

    ctx->priv_rl = new_ptr;
    uint32_t n1 = ntohl(new_ptr->n1);
    if (memcpy_S(&new_ptr->f[n1], sizeof(FpElemStr), priv, sizeof(FpElemStr)) != 0) {
      result = kEpidErr;
      break;
    }

    OCTSTR32_LOAD(new_ptr->n1, n1 + 1)
    new_ptr->version = new_ptr->n1;

    // if (!IsPrivRlValid(&ctx->ipriv_key->gid, new_ptr, GetSigRlSize(new_ptr))) {
    //   result = kEpidNotImpl;
    // }
  } while(0);

  return result;
}

EpidStatus RevokeSig(EpidSignature* sig, IssuerCtx* ctx) {
  EpidStatus result = kEpidNoErr;

  do {
    if (!sig || !ctx) {
      result = kEpidBadArgErr;
      break;
    }
    SigRl *new_ptr = realloc(ctx->sig_rl, GetSigRlSize(ctx->sig_rl) + sizeof(SigRlEntry));
    if (!new_ptr) {
      result = kEpidMemAllocErr;
      break;
    }

    ctx->sig_rl = new_ptr;
    uint32_t n2 = ntohl(new_ptr->n2);
    if (memcpy_S(&new_ptr->bk[n2].b, sizeof(G1ElemStr), &sig->sigma0.B, sizeof(G1ElemStr)) != 0
          || memcpy_S(&new_ptr->bk[n2].k, sizeof(G1ElemStr), &sig->sigma0.K, sizeof(G1ElemStr)) != 0) {
      result = kEpidErr;
      break;
    }

    OCTSTR32_LOAD(new_ptr->n2, n2 + 1)
    new_ptr->version = new_ptr->n2;

    // if (!IsSigRlValid(&ctx->ipriv_key->gid, new_ptr, GetSigRlSize(new_ptr))) {
    //   result = kEpidNotImpl;
    // }
  } while(0);

  return result;
}