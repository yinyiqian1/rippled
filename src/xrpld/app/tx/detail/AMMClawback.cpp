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

// #include <xrpl/protocol/AmountConversions.h>
#include <xrpld/app/misc/AMMHelpers.h>
#include <xrpld/app/misc/AMMUtils.h>
#include <xrpld/app/tx/detail/AMMClawback.h>
#include <xrpld/app/tx/detail/AMMWithdraw.h>
#include <xrpld/ledger/Sandbox.h>
#include <xrpld/ledger/View.h>
#include <xrpl/protocol/AMMCore.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/st.h>
#include <tuple>

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
        std::cout << "AMMClawback: holder cannot be the same as issuer."
                  << std::endl;
        return temMALFORMED;
    }

    std::optional<STAmount> const clawAmount = ctx.tx[~sfAmount];

    std::cout << "preflight: issuer " << issuer << std::endl;
    std::cout << "preflight: holder " << holder << std::endl;
    std::cout << "preflight: ammAccount " << ammAccount << std::endl;
    if (clawAmount)
    {
        std::cout << "clawAmout issuer: " << clawAmount->getIssuer()
                  << std::endl;
        std::cout << "clawAmout mantissa: " << clawAmount->mantissa()
                  << std::endl;
        std::cout << "clawAmout exponent: " << clawAmount->exponent()
                  << std::endl;
    }

    if (clawAmount && clawAmount->getIssuer() != issuer)
    {
        JLOG(ctx.j.debug()) << "AMMClawback: Amount's issuer subfield should "
                               "be the same as Account field.";
        std::cout << "AMMClawback: Amount's issuer subfield should be the same "
                     "as Account field."
                  << std::endl;
        return temBAD_AMOUNT;
    }

    if (*clawAmount < beast::zero)
    {
        JLOG(ctx.j.debug())
            << "AMMClawback: Amount being clawed back can't be less than zero.";
        std::cout
            << "AMMClawback: Amount being clawed back can't be less than zero."
            << std::endl;
        return temBAD_AMOUNT;
    }

    return preflight2(ctx);
}

TER
AMMClawback::preclaim(PreclaimContext const& ctx)
{
    AccountID const issuer = ctx.tx[sfAccount];
    AccountID const holder = ctx.tx[sfHolder];
    AccountID const ammAccount = ctx.tx[sfAMMAccount];

    auto const sleIssuer = ctx.view.read(keylet::account(issuer));
    auto const sleHolder = ctx.view.read(keylet::account(holder));
    auto const sleAMMAccount = ctx.view.read(keylet::account(ammAccount));

    if (!sleAMMAccount)
    {
        JLOG(ctx.j.debug())
            << "AMMClawback: AMMAccount provided does not exist.";
        return temMALFORMED;
    }

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

    if (asset.issue().account != issuer && asset2.issue().account != issuer)
    {
        JLOG(ctx.j.debug())
            << "AMMClawback: Account field is not the issuer of either asset "
               "in AMM pool. The two assets in the pool are: "
            << asset.issue().currency << " and " << asset2.issue().currency;

        return tecNO_PERMISSION;
    }

    return tesSUCCESS;
}

TER
AMMClawback::doApply()
{
    Sandbox sb(&ctx_.view());

    auto const result = applyGuts(sb);
    if (result.second)
        sb.apply(ctx_.rawView());

    return result.first;
}

std::pair<TER, bool>
AMMClawback::applyGuts(Sandbox& sb)
{
    std::optional<STAmount> const clawAmount = ctx_.tx[~sfAmount];
    AccountID const ammAccount = ctx_.tx[sfAMMAccount];
    AccountID const issuer = ctx_.tx[sfAccount];
    AccountID const holder = ctx_.tx[sfHolder];

    auto const sleAMMAccount = ctx_.view().read(keylet::account(ammAccount));

    if (!sleAMMAccount)
    {
        JLOG(j_.debug()) << "AMMClawback: AMMAccount provided does not exist.";
        return {temMALFORMED, false};
    }

    auto const ammID = sleAMMAccount->getFieldH256(sfAMMID);
    if (!ammID)
    {
        JLOG(j_.debug())
            << "AMMClawback: AMMAccount field is not an AMM account.";
        return {tecNO_PERMISSION, false};
    }

    auto ammSle = sb.peek(keylet::amm(ammID));
    if (!ammSle)
    {
        JLOG(j_.debug()) << "AMMClawback: can not find AMM with ammID: "
                         << ammID;
        return {tecINTERNAL, false};
    }

    auto const tfee = getTradingFee(ctx_.view(), *ammSle, ammAccount);
    Issue const& issue1 = ammSle->getFieldIssue(sfAsset).issue();
    Issue const& issue2 = ammSle->getFieldIssue(sfAsset2).issue();

    if (!clawAmount)
        return clawbackAll(sb, ammSle, ammAccount, issuer, holder);

    Issue currentIssue = clawAmount->issue();
    Issue otherIssue;

    if (currentIssue == issue1)
        otherIssue = issue2;
    else if (currentIssue == issue2)
        otherIssue = issue1;
    else
        return {tecINTERNAL, false};

    auto const expected = ammHolds(
        sb,
        *ammSle,
        currentIssue,
        otherIssue,
        FreezeHandling::fhZERO_IF_FROZEN,
        ctx_.journal);

    if (!expected)
        return {expected.error(), false};
    auto const [amountBalance, amount2Balance, lptAMMBalance] = *expected;

    auto [result, newLPTokenBalance] = equalWithdrawMatchingOneAmount(
        sb,
        *ammSle,
        holder,
        ammAccount,
        amountBalance,
        amount2Balance,
        lptAMMBalance,
        *clawAmount,
        tfee);

    if (result != tesSUCCESS)
        return {result, false};

    auto const res = deleteAMMAccountIfEmpty(
        sb, ammSle, newLPTokenBalance, issue1, issue2, j_);
    if (!res.second)
        return {res.first, false};

    JLOG(ctx_.journal.trace())
        << "AMM Withdraw during AMMClawback: lptoken new balance: "
        << to_string(newLPTokenBalance.iou())
        << " old balance: " << to_string(lptAMMBalance.iou());

    auto const ter = rippleCredit(sb, holder, issuer, *clawAmount, true, j_);

    if (ter != tesSUCCESS)
        return {ter, false};

    return {tesSUCCESS, true};
}

std::pair<TER, bool>
AMMClawback::clawbackAll(
    Sandbox& sb,
    const std::shared_ptr<SLE> ammSle,
    AccountID const& ammAccount,
    AccountID const& issuer,
    AccountID const& holder)
{
    auto const tfee = getTradingFee(ctx_.view(), *ammSle, ammAccount);
    Issue const& issue1 = ammSle->getFieldIssue(sfAsset).issue();
    Issue const& issue2 = ammSle->getFieldIssue(sfAsset2).issue();
    bool accountIssuesBoth = false;
    Issue currentIssue = issue1;
    Issue otherIssue = issue2;
    if (issue1.account == issuer && issue2.account == issuer)
        accountIssuesBoth = true;
    else if (issue1.account != issuer && issue2.account == issuer)
    {
        currentIssue = issue2;
        otherIssue = issue1;
    }
    else if (issue1.account != issuer && issue2.account != issuer)
        return {tecINTERNAL, false};

    auto const expected = ammHolds(
        sb,
        *ammSle,
        currentIssue,
        otherIssue,
        FreezeHandling::fhZERO_IF_FROZEN,
        ctx_.journal);

    if (!expected)
        return {expected.error(), false};
    auto const [amountBalance, amount2Balance, lptAMMBalance] = *expected;

    auto const lpTokenBalance = ammSle->getFieldAmount(sfLPTokenBalance);
    STAmount const holdLPtokens = accountHolds(
        view(),
        holder,
        lpTokenBalance.getCurrency(),
        lpTokenBalance.getIssuer(),
        fhIGNORE_FREEZE,
        j_);

    auto [result, newLPTokenBalance, amount1Withdraw, amount2Withdraw] =
        AMMWithdraw::equalWithdrawTokens(
            sb,
            *ammSle,
            holder,
            ammAccount,
            amountBalance,
            amount2Balance,
            lptAMMBalance,
            holdLPtokens,
            holdLPtokens,
            tfee,
            ctx_.journal,
            ctx_.tx);

    if (result != tesSUCCESS)
        return {result, false};

    auto const res = deleteAMMAccountIfEmpty(
        sb, ammSle, newLPTokenBalance, issue1, issue2, j_);
    if (!res.second)
        return {res.first, false};

    JLOG(ctx_.journal.trace())
        << "AMM Withdraw during AMMClawback: lptoken new balance: "
        << to_string(newLPTokenBalance.iou())
        << " old balance: " << to_string(lptAMMBalance.iou());

    auto const ter =
        rippleCredit(sb, holder, issuer, amount1Withdraw, true, j_);

    if (ter != tesSUCCESS)
        return {ter, false};

    if (accountIssuesBoth)
    {
        auto const ter =
            rippleCredit(sb, holder, issuer, *amount2Withdraw, true, j_);

        if (ter != tesSUCCESS)
            return {ter, false};
    }

    return {tesSUCCESS, true};
}

std::tuple<TER, STAmount>
AMMClawback::equalWithdrawMatchingOneAmount(
    Sandbox& view,
    SLE const& ammSle,
    AccountID const& holder,
    AccountID const& ammAccount,
    STAmount const& amountBalance,
    STAmount const& amount2Balance,
    STAmount const& lptAMMBalance,
    STAmount const& amount,
    std::uint16_t tfee)
{
    auto frac = Number{amount} / amountBalance;
    auto const amount2Withdraw = amount2Balance * frac;
    TER result;
    STAmount newLPTokenBalance;
    std::tie(result, newLPTokenBalance, std::ignore, std::ignore) = withdraw(
        view,
        ammAccount,
        holder,
        ammSle,
        amountBalance,
        amount,
        toSTAmount(amount2Balance.issue(), amount2Withdraw),
        lptAMMBalance,
        toSTAmount(lptAMMBalance.issue(), lptAMMBalance * frac),
        tfee,
        ctx_.journal,
        ctx_.tx);
    return {result, newLPTokenBalance};
}

}  // namespace ripple
