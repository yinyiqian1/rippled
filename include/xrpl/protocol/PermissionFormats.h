//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2024 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#ifndef RIPPLE_PROTOCOL_PERMISSIONFORMATS_H_INCLUDED
#define RIPPLE_PROTOCOL_PERMISSIONFORMATS_H_INCLUDED

#include <xrpl/protocol/KnownFormats.h>

namespace ripple {

/** Permission type identifiers.

    These are part of the binary message format.

    @ingroup protocol
*/
enum PermissionType : std::uint16_t {
    tpPAYMENT = 1,

    tpESCROW_CREATE = 2,

    tpESCROW_FINISH = 3,

    tpACCOUNT_SET = 4,

    tpESCROW_CANCEL = 5,

    tpREGULAR_KEY_SET = 6,

    tpNICKNAME_SET [[deprecated(
        "This transaction type is not supported and should not be used.")]] = 7,

    tpOFFER_CREATE = 8,

    tpOFFER_CANCEL = 9,

    tpCONTRACT [[deprecated(
        "This transaction type is not supported and should not be used.")]] =
        10,

    tpTICKET_CREATE = 11,

    tpSPINAL_TAP [[deprecated(
        "This transaction type is not supported and should not be used.")]] =
        12,

    tpSIGNER_LIST_SET = 13,

    tpPAYCHAN_CREATE = 14,

    tpPAYCHAN_FUND = 15,

    tpPAYCHAN_CLAIM = 16,

    tpCHECK_CREATE = 17,

    tpCHECK_CASH = 18,

    tpCHECK_CANCEL = 19,

    tpDEPOSIT_PREAUTH = 20,

    tpTRUST_SET = 21,

    tpACCOUNT_DELETE = 22,

    tpHOOK_SET [[maybe_unused]] = 23,

    tpNFTOKEN_MINT = 26,

    tpNFTOKEN_BURN = 27,

    tpNFTOKEN_CREATE_OFFER = 28,

    tpNFTOKEN_CANCEL_OFFER = 29,

    tpNFTOKEN_ACCEPT_OFFER = 30,

    tpCLAWBACK = 31,

    tpAMM_CREATE = 36,

    tpAMM_DEPOSIT = 37,

    tpAMM_WITHDRAW = 38,

    tpAMM_VOTE = 39,

    tpAMM_BID = 40,

    tpAMM_DELETE = 41,

    tpXCHAIN_CREATE_CLAIM_ID = 42,

    tpXCHAIN_COMMIT = 43,

    tpXCHAIN_CLAIM = 44,

    tpXCHAIN_ACCOUNT_CREATE_COMMIT = 45,

    tpXCHAIN_ADD_CLAIM_ATTESTATION = 46,

    tpXCHAIN_ADD_ACCOUNT_CREATE_AtpESTATION = 47,

    tpXCHAIN_MODIFY_BRIDGE = 48,

    tpXCHAIN_CREATE_BRIDGE = 49,

    tpDID_SET = 50,

    tpDID_DELETE = 51,

    tpORACLE_SET = 52,

    tpORACLE_DELETE = 53,

    tpLEDGER_STATE_FIX = 54,
};

enum GranularPermissionType : std::uint32_t {
    gpTrustlineAuthorize = 65537,

    gpTrustlineFreeze = 65538,

    gpTrustlineUnfreeze = 65539,

    gpAccountDomainSet = 65540,

    gpAccountEmailHashSet = 65541,

    gpAccountMessageKeySet = 65542,

    gpAccountTransferRateSet = 65543,

    gpAccountTickSizeSet = 65544,

    gpPaymentMint = 65545,

    gpPaymentBurn = 65546,

    gpMPTokenIssuanceLock = 65547,

    gpMPTokenIssuanceUnlock = 65548,
};

/** Manages the list of known granular permission formats.
 */
class GranularPermissionFormats
    : public KnownFormats<GranularPermissionType, GranularPermissionFormats>
{
private:
    /** Create the object.
        This will load the object with all the known granular permission
       formats.
    */
    GranularPermissionFormats();

public:
    static GranularPermissionFormats const&
    getInstance();
};

}  // namespace ripple

#endif
