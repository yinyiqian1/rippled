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

#include <xrpld/app/tx/detail/AMMClawback.h>
#include <xrpld/ledger/View.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/st.h>

namespace ripple {

NotTEC
AMMClawback::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureClawback))
        return temDISABLED;

    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    if (ctx.tx.getFlags() & tfClawbackMask)
        return temINVALID_FLAG;

    AccountID const issuer = ctx.tx[sfAccount];
    AccountID const holder = ctx.tx[sfHolder];
    AccountID const ammAccount = ctx.tx[sfAMMAccount];
    
    if (issuer == holder)
    {
        JLOG(ctx.j.debug())
            << "AMMClawback: holder cannot be the same as issuer.";
        return temMALFORMED;
    }

    std::cout << "preflight: issuer " << issuer << std::endl;
    std::cout << "preflight: holder " << holder << std::endl;
    std::cout << "preflight: ammAccount " << ammAccount << std::endl;

    STAmount const clawAmount = ctx.tx[sfAmount];
    
    if (clawAmount && clawAmount.getIssuer() != issuer)
    {
        JLOG(ctx.j.debug()) << "AMMClawback: Amount's issuer subfield should be the same as AMMAccount field.";
        return temMALFORMED;
    }

    return preflight2(ctx);
}

TER
AMMClawback::preclaim(PreclaimContext const& ctx)
{
    AccountID const issuer = ctx.tx[sfAccount];
    AccountID const holder = ctx.tx[sfHolder];
    AccountID const ammAccount = ctx.tx[sfAMMAccount];
    STAmount const clawAmount = ctx.tx[sfAmount];
    
    auto const sleIssuer = ctx.view.read(keylet::account(issuer));
    auto const sleHolder = ctx.view.read(keylet::account(holder));
    auto const sleAMMAccount = ctx.view.read(keylet::account(ammAccount));

    std::uint32_t const issuerFlagsIn = sleIssuer->getFieldU32(sfFlags);

    // If AllowTrustLineClawback is not set or NoFreeze is set, return no
    // permission
    // if (!(issuerFlagsIn & lsfAllowTrustLineClawback) ||
    //     (issuerFlagsIn & lsfNoFreeze))
    //     return tecNO_PERMISSION;
    

    // if (!sleAMMAccount->isFieldPresent(sfAMMID))
    // {
    //     std::cout << "Error: AMMID not present" << std::endl;
    //     return tecNO_PERMISSION;
    // }

    auto const ammID = sleAMMAccount->getFieldH256(sfAMMID);
    if (!ammID)
    {
        JLOG(ctx.j.debug()) << "AMMClawback: AMMAccount field is not an AMM account.";
        return tecNO_PERMISSION;
    }

    std::cout << "amm ID: " << ammID << std::endl;

    auto const sleAMM = ctx.view.read(keylet::amm(ammID));
    if (!sleAMM)
    {
        JLOG(ctx.j.debug()) << "AMMClawback: can not find AMM with ammID: " << ammID;
        return tecINTERNAL;
    }

    STIssue const& asset = sleAMM->getFieldIssue(sfAsset);
    STIssue const& asset2 = sleAMM->getFieldIssue(sfAsset2);

    std::cout << "asset currency: " << asset.issue().currency << std::endl;
    std::cout << "asset2 currency: " << asset2.issue().currency << std::endl;

    auto const lpTokenBalance = sleAMM->getFieldAmount(sfLPTokenBalance);
    auto const lpTokenCurrency = lpTokenBalance.getCurrency();

    std::cout << "lpTokenCurrency: " << lpTokenCurrency << std::endl;

    // if (lpTokenCurrency != clawAmount->getCurrency())
    // {
    //     JLOG(ctx.j.debug()) << "AMMClawback: Amount's currency subfield does not match with the specified AMMAccount";
    //     return tecINTERNAL;
    // }
    // check trust line between holder and AMM account
    // auto const sleRippleState =
    //     ctx.view.read(keylet::line(holder, ammAccount, lpTokenCurrency));
    // if (!sleRippleState)
    //     return tecNO_LINE;

    // STAmount const balance = (*sleRippleState)[sfBalance];

    // // If balance is positive, ammAccount must have higher address than holder
    // if (balance > beast::zero && ammAccount < holder)
    //     return tecNO_PERMISSION;

    // // If balance is negative, ammAccount must have lower address than holder
    // if (balance < beast::zero && ammAccount > holder)
    //     return tecNO_PERMISSION;
}

TER
AMMClawback::doApply()
{
   
}

}  // namespace ripple
