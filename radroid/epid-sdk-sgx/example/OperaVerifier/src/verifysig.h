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
 * \brief Signature verification interface.
 */
#ifndef EXAMPLE_VERIFYSIG_SRC_VERIFYSIG_H_
#define EXAMPLE_VERIFYSIG_SRC_VERIFYSIG_H_

#include <stddef.h>
#include "epid/common/errors.h"
#include "epid/common/stdtypes.h"
#include "epid/common/types.h"
#include "ext/Opera/opera_types.h"
#include <android/log.h>

#define APNAME "Verifier"


/// verify Intel(R) EPID 2.x signature
int Verify(uint8_t const* p_gvcert, uint8_t *p_asquote, uint8_t *p_srl, int sig_rl_size, uint8_t *p_prl, int priv_rl_size);
#endif  // EXAMPLE_VERIFYSIG_SRC_VERIFYSIG_H_
