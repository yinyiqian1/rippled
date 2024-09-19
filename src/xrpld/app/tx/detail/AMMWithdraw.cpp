//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2023 Ripple Labs Inc.

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

#include <xrpld/app/tx/detail/AMMWithdraw.h>

#include <xrpld/app/misc/AMMHelpers.h>
#include <xrpld/app/misc/AMMUtils.h>
#include <xrpld/ledger/Sandbox.h>
#include <xrpld/ledger/View.h>
#include <xrpl/basics/Number.h>
#include <xrpl/protocol/AMMCore.h>
#include <xrpl/protocol/STAccount.h>
#include <xrpl/protocol/TxFlags.h>

#include <bit>

namespace ripple {

NotTEC
AMMWithdraw::preflight(PreflightContext const& ctx)
{
    if (!ammEnabled(ctx.rules))
        return temDISABLED;

    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    auto const flags = ctx.tx.getFlags();
    if (flags & tfWithdrawMask)
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid flags.";
        return temINVALID_FLAG;
    }

    auto const amount = ctx.tx[~sfAmount];
    auto const amount2 = ctx.tx[~sfAmount2];
    auto const ePrice = ctx.tx[~sfEPrice];
    auto const lpTokens = ctx.tx[~sfLPTokenIn];
    // Valid combinations are:
    //   LPTokens
    //   tfWithdrawAll
    //   Amount
    //   tfOneAssetWithdrawAll & Amount
    //   Amount and Amount2
    //   Amount and LPTokens
    //   Amount and EPrice
    if (std::popcount(flags & tfWithdrawSubTx) != 1)
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid flags.";
        return temMALFORMED;
    }
    if (flags & tfLPToken)
    {
        if (!lpTokens || amount || amount2 || ePrice)
            return temMALFORMED;
    }
    else if (flags & tfWithdrawAll)
    {
        if (lpTokens || amount || amount2 || ePrice)
            return temMALFORMED;
    }
    else if (flags & tfOneAssetWithdrawAll)
    {
        if (!amount || lpTokens || amount2 || ePrice)
            return temMALFORMED;
    }
    else if (flags & tfSingleAsset)
    {
        if (!amount || lpTokens || amount2 || ePrice)
            return temMALFORMED;
    }
    else if (flags & tfTwoAsset)
    {
        if (!amount || !amount2 || lpTokens || ePrice)
            return temMALFORMED;
    }
    else if (flags & tfOneAssetLPToken)
    {
        if (!amount || !lpTokens || amount2 || ePrice)
            return temMALFORMED;
    }
    else if (flags & tfLimitLPToken)
    {
        if (!amount || !ePrice || lpTokens || amount2)
            return temMALFORMED;
    }

    auto const asset = ctx.tx[sfAsset];
    auto const asset2 = ctx.tx[sfAsset2];
    if (auto const res = invalidAMMAssetPair(asset, asset2))
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: Invalid asset pair.";
        return res;
    }

    if (amount && amount2 && amount->issue() == amount2->issue())
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid tokens, same issue."
                            << amount->issue() << " " << amount2->issue();
        return temBAD_AMM_TOKENS;
    }

    if (lpTokens && *lpTokens <= beast::zero)
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid tokens.";
        return temBAD_AMM_TOKENS;
    }

    if (amount)
    {
        if (auto const res = invalidAMMAmount(
                *amount,
                std::make_optional(std::make_pair(asset, asset2)),
                (flags & (tfOneAssetWithdrawAll | tfOneAssetLPToken)) ||
                    ePrice))
        {
            JLOG(ctx.j.debug()) << "AMM Withdraw: invalid Asset1Out";
            return res;
        }
    }

    if (amount2)
    {
        if (auto const res = invalidAMMAmount(
                *amount2, std::make_optional(std::make_pair(asset, asset2))))
        {
            JLOG(ctx.j.debug()) << "AMM Withdraw: invalid Asset2OutAmount";
            return res;
        }
    }

    if (ePrice)
    {
        if (auto const res = invalidAMMAmount(*ePrice))
        {
            JLOG(ctx.j.debug()) << "AMM Withdraw: invalid EPrice";
            return res;
        }
    }

    return preflight2(ctx);
}

static std::optional<STAmount>
tokensWithdraw(
    STAmount const& lpTokens,
    std::optional<STAmount> const& tokensIn,
    std::uint32_t flags)
{
    if (flags & (tfWithdrawAll | tfOneAssetWithdrawAll))
        return lpTokens;
    return tokensIn;
}

TER
AMMWithdraw::preclaim(PreclaimContext const& ctx)
{
    auto const accountID = ctx.tx[sfAccount];

    auto const ammSle =
        ctx.view.read(keylet::amm(ctx.tx[sfAsset], ctx.tx[sfAsset2]));
    if (!ammSle)
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: Invalid asset pair.";
        return terNO_AMM;
    }

    auto const amount = ctx.tx[~sfAmount];
    auto const amount2 = ctx.tx[~sfAmount2];

    auto const expected = ammHolds(
        ctx.view,
        *ammSle,
        amount ? amount->issue() : std::optional<Issue>{},
        amount2 ? amount2->issue() : std::optional<Issue>{},
        FreezeHandling::fhIGNORE_FREEZE,
        ctx.j);
    if (!expected)
        return expected.error();
    auto const [amountBalance, amount2Balance, lptAMMBalance] = *expected;
    if (lptAMMBalance == beast::zero)
        return tecAMM_EMPTY;
    if (amountBalance <= beast::zero || amount2Balance <= beast::zero ||
        lptAMMBalance < beast::zero)
    {
        JLOG(ctx.j.debug())
            << "AMM Withdraw: reserves or tokens balance is zero.";
        return tecINTERNAL;  // LCOV_EXCL_LINE
    }

    auto const ammAccountID = ammSle->getAccountID(sfAccount);

    auto checkAmount = [&](std::optional<STAmount> const& amount,
                           auto const& balance) -> TER {
        if (amount)
        {
            if (amount > balance)
            {
                JLOG(ctx.j.debug())
                    << "AMM Withdraw: withdrawing more than the balance, "
                    << *amount;
                return tecAMM_BALANCE;
            }
            if (auto const ter =
                    requireAuth(ctx.view, amount->issue(), accountID))
            {
                JLOG(ctx.j.debug())
                    << "AMM Withdraw: account is not authorized, "
                    << amount->issue();
                return ter;
            }
            // AMM account or currency frozen
            if (isFrozen(ctx.view, ammAccountID, amount->issue()))
            {
                JLOG(ctx.j.debug())
                    << "AMM Withdraw: AMM account or currency is frozen, "
                    << to_string(accountID);
                return tecFROZEN;
            }
            // Account frozen
            if (isIndividualFrozen(ctx.view, accountID, amount->issue()))
            {
                JLOG(ctx.j.debug()) << "AMM Withdraw: account is frozen, "
                                    << to_string(accountID) << " "
                                    << to_string(amount->issue().currency);
                return tecFROZEN;
            }
        }
        return tesSUCCESS;
    };

    if (auto const ter = checkAmount(amount, amountBalance))
        return ter;

    if (auto const ter = checkAmount(amount2, amount2Balance))
        return ter;

    auto const lpTokens =
        ammLPHolds(ctx.view, *ammSle, ctx.tx[sfAccount], ctx.j);
    auto const lpTokensWithdraw =
        tokensWithdraw(lpTokens, ctx.tx[~sfLPTokenIn], ctx.tx.getFlags());

    if (lpTokens <= beast::zero)
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: tokens balance is zero.";
        return tecAMM_BALANCE;
    }

    if (lpTokensWithdraw && lpTokensWithdraw->issue() != lpTokens.issue())
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid LPTokens.";
        return temBAD_AMM_TOKENS;
    }

    if (lpTokensWithdraw && *lpTokensWithdraw > lpTokens)
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid tokens.";
        return tecAMM_INVALID_TOKENS;
    }

    if (auto const ePrice = ctx.tx[~sfEPrice];
        ePrice && ePrice->issue() != lpTokens.issue())
    {
        JLOG(ctx.j.debug()) << "AMM Withdraw: invalid EPrice.";
        return temBAD_AMM_TOKENS;
    }

    if (ctx.tx.getFlags() & (tfLPToken | tfWithdrawAll))
    {
        if (auto const ter = checkAmount(amountBalance, amountBalance))
            return ter;
        if (auto const ter = checkAmount(amount2Balance, amount2Balance))
            return ter;
    }

    return tesSUCCESS;
}

std::pair<TER, bool>
AMMWithdraw::applyGuts(Sandbox& sb)
{
    auto const amount = ctx_.tx[~sfAmount];
    auto const amount2 = ctx_.tx[~sfAmount2];
    auto const ePrice = ctx_.tx[~sfEPrice];
    auto ammSle = sb.peek(keylet::amm(ctx_.tx[sfAsset], ctx_.tx[sfAsset2]));
    if (!ammSle)
        return {tecINTERNAL, false};  // LCOV_EXCL_LINE
    auto const ammAccountID = (*ammSle)[sfAccount];
    auto const accountSle = sb.read(keylet::account(ammAccountID));
    if (!accountSle)
        return {tecINTERNAL, false};  // LCOV_EXCL_LINE
    auto const lpTokens =
        ammLPHolds(ctx_.view(), *ammSle, ctx_.tx[sfAccount], ctx_.journal);
    auto const lpTokensWithdraw =
        tokensWithdraw(lpTokens, ctx_.tx[~sfLPTokenIn], ctx_.tx.getFlags());

    // Due to rounding, the LPTokenBalance of the last LP
    // might not match the LP's trustline balance
    if (sb.rules().enabled(fixAMMv1_1))
    {
        if (auto const res =
                isOnlyLiquidityProvider(sb, lpTokens.issue(), account_);
            !res)
            return {res.error(), false};
        else if (res.value())
        {
            if (withinRelativeDistance(
                    lpTokens,
                    ammSle->getFieldAmount(sfLPTokenBalance),
                    Number{1, -3}))
            {
                ammSle->setFieldAmount(sfLPTokenBalance, lpTokens);
                sb.update(ammSle);
            }
            else
            {
                return {tecAMM_INVALID_TOKENS, false};
            }
        }
    }

    auto const tfee = getTradingFee(ctx_.view(), *ammSle, account_);

    auto const expected = ammHolds(
        sb,
        *ammSle,
        amount ? amount->issue() : std::optional<Issue>{},
        amount2 ? amount2->issue() : std::optional<Issue>{},
        FreezeHandling::fhZERO_IF_FROZEN,
        ctx_.journal);
    if (!expected)
        return {expected.error(), false};
    auto const [amountBalance, amount2Balance, lptAMMBalance] = *expected;

    auto const subTxType = ctx_.tx.getFlags() & tfWithdrawSubTx;

    auto const [result, newLPTokenBalance] =
        [&,
         &amountBalance = amountBalance,
         &amount2Balance = amount2Balance,
         &lptAMMBalance = lptAMMBalance]() -> std::pair<TER, STAmount> {
        if (subTxType & tfTwoAsset)
            return equalWithdrawLimit(
                sb,
                *ammSle,
                ammAccountID,
                amountBalance,
                amount2Balance,
                lptAMMBalance,
                *amount,
                *amount2,
                tfee);
        if (subTxType & tfOneAssetLPToken || subTxType & tfOneAssetWithdrawAll)
            return singleWithdrawTokens(
                sb,
                *ammSle,
                ammAccountID,
                amountBalance,
                lptAMMBalance,
                *amount,
                *lpTokensWithdraw,
                tfee);
        if (subTxType & tfLimitLPToken)
            return singleWithdrawEPrice(
                sb,
                *ammSle,
                ammAccountID,
                amountBalance,
                lptAMMBalance,
                *amount,
                *ePrice,
                tfee);
        if (subTxType & tfSingleAsset)
            return singleWithdraw(
                sb,
                *ammSle,
                ammAccountID,
                amountBalance,
                lptAMMBalance,
                *amount,
                tfee);
        if (subTxType & tfLPToken || subTxType & tfWithdrawAll)
        {
            TER result;
            STAmount newLPTokenBalance;
            bool withdrawAll =
                ctx_.tx[sfFlags] & (tfWithdrawAll | tfOneAssetWithdrawAll);
            std::tie(result, newLPTokenBalance, std::ignore, std::ignore) =
                equalWithdrawTokens(
                    sb,
                    *ammSle,
                    account_,
                    ammAccountID,
                    amountBalance,
                    amount2Balance,
                    lptAMMBalance,
                    lpTokens,
                    *lpTokensWithdraw,
                    tfee,
                    ctx_.journal,
                    ctx_.tx,
                    withdrawAll);
            return {result, newLPTokenBalance};
        }
        // should not happen.
        // LCOV_EXCL_START
        JLOG(j_.error()) << "AMM Withdraw: invalid options.";
        return std::make_pair(tecINTERNAL, STAmount{});
        // LCOV_EXCL_STOP
    }();

    if (result != tesSUCCESS)
        return {result, false};

    auto const res = deleteAMMAccountIfEmpty(
        sb, ammSle, newLPTokenBalance, ctx_.tx[sfAsset], ctx_.tx[sfAsset2], j_);
    if (!res.second)
        return {res.first, false};

    JLOG(ctx_.journal.trace())
        << "AMM Withdraw: tokens " << to_string(newLPTokenBalance.iou()) << " "
        << to_string(lpTokens.iou()) << " " << to_string(lptAMMBalance.iou());

    return {tesSUCCESS, true};
}

TER
AMMWithdraw::doApply()
{
    // This is the ledger view that we work against. Transactions are applied
    // as we go on processing transactions.
    Sandbox sb(&ctx_.view());

    auto const result = applyGuts(sb);
    if (result.second)
        sb.apply(ctx_.rawView());

    return result.first;
}

/** Proportional withdrawal of pool assets for the amount of LPTokens.
 */
std::tuple<TER, STAmount, STAmount, std::optional<STAmount>>
AMMWithdraw::equalWithdrawTokens(
    Sandbox& view,
    SLE const& ammSle,
    AccountID const account,
    AccountID const& ammAccount,
    STAmount const& amountBalance,
    STAmount const& amount2Balance,
    STAmount const& lptAMMBalance,
    STAmount const& lpTokens,
    STAmount const& lpTokensWithdraw,
    std::uint16_t tfee,
    beast::Journal const& journal,
    STTx const& tx,
    bool withdrawAll)
{
    try
    {
        // Withdrawing all tokens in the pool
        if (lpTokensWithdraw == lptAMMBalance)
        {
            return withdraw(
                view,
                ammAccount,
                account,
                ammSle,
                amountBalance,
                amountBalance,
                amount2Balance,
                lptAMMBalance,
                lpTokensWithdraw,
                tfee,
                journal,
                tx,
                true);
        }

        auto const frac = divide(lpTokensWithdraw, lptAMMBalance, noIssue());
        auto const withdrawAmount =
            multiply(amountBalance, frac, amountBalance.issue());
        auto const withdraw2Amount =
            multiply(amount2Balance, frac, amount2Balance.issue());
        // LP is making equal withdrawal by tokens but the requested amount
        // of LP tokens is likely too small and results in one-sided pool
        // withdrawal due to round off. Fail so the user withdraws
        // more tokens.
        if (withdrawAmount == beast::zero || withdraw2Amount == beast::zero)
            return {tecAMM_FAILED, STAmount{}, STAmount{}, STAmount{}};

        return withdraw(
            view,
            ammAccount,
            account,
            ammSle,
            amountBalance,
            withdrawAmount,
            withdraw2Amount,
            lptAMMBalance,
            lpTokensWithdraw,
            tfee,
            journal,
            tx,
            withdrawAll);
    }
    // LCOV_EXCL_START
    catch (std::exception const& e)
    {
        JLOG(journal.error())
            << "AMMWithdraw::equalWithdrawTokens exception " << e.what();
    }
    return {tecINTERNAL, STAmount{}, STAmount{}, STAmount{}};
    // LCOV_EXCL_STOP
}

/** All assets withdrawal with the constraints on the maximum amount
 * of each asset that the trader is willing to withdraw.
 *       a = (t/T) * A (5)
 *       b = (t/T) * B (6)
 *       where
 *      A,B: current pool composition
 *      T: current balance of outstanding LPTokens
 *      a: balance of asset A being withdrawn
 *      b: balance of asset B being withdrawn
 *      t: balance of LPTokens issued to LP after a successful transaction
 * Use equation 5 to compute t, given the amount in Asset1Out. Let this be Z
 * Use equation 6 to compute the amount of asset2, given Z. Let
 *     the computed amount of asset2 be X
 * If X <= amount in Asset2Out:
 *   The amount of asset1 to be withdrawn is the one specified in Asset1Out
 *   The amount of asset2 to be withdrawn is X
 *   The amount of LPTokens redeemed is Z
 * If X> amount in Asset2Out:
 *   Use equation 5 to compute t, given the amount in Asset2Out. Let this be Q
 *   Use equation 6 to compute the amount of asset1, given Q.
 *     Let the computed amount of asset1 be W
 *   The amount of asset2 to be withdrawn is the one specified in Asset2Out
 *   The amount of asset1 to be withdrawn is W
 *   The amount of LPTokens redeemed is Q
 */
std::pair<TER, STAmount>
AMMWithdraw::equalWithdrawLimit(
    Sandbox& view,
    SLE const& ammSle,
    AccountID const& ammAccount,
    STAmount const& amountBalance,
    STAmount const& amount2Balance,
    STAmount const& lptAMMBalance,
    STAmount const& amount,
    STAmount const& amount2,
    std::uint16_t tfee)
{
    TER result;
    STAmount newLPTokenBalance;
    auto frac = Number{amount} / amountBalance;
    auto const amount2Withdraw = amount2Balance * frac;
    bool withdrawAll =
        ctx_.tx[sfFlags] & (tfWithdrawAll | tfOneAssetWithdrawAll);
    if (amount2Withdraw <= amount2)
    {
        std::tie(result, newLPTokenBalance, std::ignore, std::ignore) =
            withdraw(
                view,
                ammAccount,
                account_,
                ammSle,
                amountBalance,
                amount,
                toSTAmount(amount2.issue(), amount2Withdraw),
                lptAMMBalance,
                toSTAmount(lptAMMBalance.issue(), lptAMMBalance * frac),
                tfee,
                ctx_.journal,
                ctx_.tx,
                withdrawAll);
        return {result, newLPTokenBalance};
    }

    frac = Number{amount2} / amount2Balance;
    auto const amountWithdraw = amountBalance * frac;
    assert(amountWithdraw <= amount);
    std::tie(result, newLPTokenBalance, std::ignore, std::ignore) = withdraw(
        view,
        ammAccount,
        account_,
        ammSle,
        amountBalance,
        toSTAmount(amount.issue(), amountWithdraw),
        amount2,
        lptAMMBalance,
        toSTAmount(lptAMMBalance.issue(), lptAMMBalance * frac),
        tfee,
        ctx_.journal,
        ctx_.tx,
        withdrawAll);
    return {result, newLPTokenBalance};
}

/** Withdraw single asset equivalent to the amount specified in Asset1Out.
 * t = T * (c - sqrt(c**2 - 4*R))/2
 *     where R = b/B, c = R*fee + 2 - fee
 * Use equation 7 to compute the t, given the amount in Asset1Out.
 */
std::pair<TER, STAmount>
AMMWithdraw::singleWithdraw(
    Sandbox& view,
    SLE const& ammSle,
    AccountID const& ammAccount,
    STAmount const& amountBalance,
    STAmount const& lptAMMBalance,
    STAmount const& amount,
    std::uint16_t tfee)
{
    auto const tokens = lpTokensOut(amountBalance, amount, lptAMMBalance, tfee);
    if (tokens == beast::zero)
        return {tecAMM_FAILED, STAmount{}};

    TER result;
    STAmount newLPTokenBalance;
    bool withdrawAll =
        ctx_.tx[sfFlags] & (tfWithdrawAll | tfOneAssetWithdrawAll);
    std::tie(result, newLPTokenBalance, std::ignore, std::ignore) = withdraw(
        view,
        ammAccount,
        account_,
        ammSle,
        amountBalance,
        amount,
        std::nullopt,
        lptAMMBalance,
        tokens,
        tfee,
        ctx_.journal,
        ctx_.tx,
        withdrawAll);

    return {result, newLPTokenBalance};
}

/** withdrawal of single asset specified in Asset1Out proportional
 * to the share represented by the amount of LPTokens.
 * Use equation 8 to compute the amount of asset1, given the redeemed t
 *   represented by LPTokens. Let this be Y.
 * If (amount exists for Asset1Out & Y >= amount in Asset1Out) ||
 *       (amount field does not exist for Asset1Out):
 *   The amount of asset out is Y
 *   The amount of LPTokens redeemed is LPTokens
 *  Equation 8 solves equation 7 @see singleWithdraw for b.
 */
std::pair<TER, STAmount>
AMMWithdraw::singleWithdrawTokens(
    Sandbox& view,
    SLE const& ammSle,
    AccountID const& ammAccount,
    STAmount const& amountBalance,
    STAmount const& lptAMMBalance,
    STAmount const& amount,
    STAmount const& lpTokensWithdraw,
    std::uint16_t tfee)
{
    auto const amountWithdraw =
        withdrawByTokens(amountBalance, lptAMMBalance, lpTokensWithdraw, tfee);
    if (amount == beast::zero || amountWithdraw >= amount)
    {
        TER result;
        STAmount newLPTokenBalance;
        bool withdrawAll =
            ctx_.tx[sfFlags] & (tfWithdrawAll | tfOneAssetWithdrawAll);
        std::tie(result, newLPTokenBalance, std::ignore, std::ignore) =
            withdraw(
                view,
                ammAccount,
                account_,
                ammSle,
                amountBalance,
                amountWithdraw,
                std::nullopt,
                lptAMMBalance,
                lpTokensWithdraw,
                tfee,
                ctx_.journal,
                ctx_.tx,
                withdrawAll);

        return {result, newLPTokenBalance};
    }

    return {tecAMM_FAILED, STAmount{}};
}

/** Withdraw single asset with two constraints.
 * a. amount of asset1 if specified (not 0) in Asset1Out specifies the minimum
 *     amount of asset1 that the trader is willing to withdraw.
 * b. The effective price of asset traded out does not exceed the amount
 *     specified in EPrice
 *       The effective price (EP) of a trade is defined as the ratio
 *       of the tokens the trader sold or swapped in (Token B) and
 *       the token they got in return or swapped out (Token A).
 *       EP(B/A) = b/a (III)
 *       b = B * (t1**2 + t1*(f - 2))/(t1*f - 1) (8)
 *           where t1 = t/T
 * Use equations 8 & III and amount in EPrice to compute the two variables:
 *   asset in as LPTokens. Let this be X
 *   asset out as that in Asset1Out. Let this be Y
 * If (amount exists for Asset1Out & Y >= amount in Asset1Out) ||
 *     (amount field does not exist for Asset1Out):
 *   The amount of assetOut is given by Y
 *   The amount of LPTokens is given by X
 */
std::pair<TER, STAmount>
AMMWithdraw::singleWithdrawEPrice(
    Sandbox& view,
    SLE const& ammSle,
    AccountID const& ammAccount,
    STAmount const& amountBalance,
    STAmount const& lptAMMBalance,
    STAmount const& amount,
    STAmount const& ePrice,
    std::uint16_t tfee)
{
    // LPTokens is asset in => E = t / a and formula (8) is:
    // a = A*(t1**2 + t1*(f - 2))/(t1*f - 1)
    // substitute a as t/E =>
    // t/E = A*(t1**2 + t1*(f - 2))/(t1*f - 1), t1=t/T => t = t1*T
    // t1*T/E = A*((t/T)**2 + t*(f - 2)/T)/(t*f/T - 1) =>
    // T/E = A*(t1 + f-2)/(t1*f - 1) =>
    // T*(t1*f - 1) = A*E*(t1 + f - 2) =>
    // t1*T*f - T = t1*A*E + A*E*(f - 2) =>
    // t1*(T*f - A*E) = T + A*E*(f - 2) =>
    // t = T*(T + A*E*(f - 2))/(T*f - A*E)
    Number const ae = amountBalance * ePrice;
    auto const f = getFee(tfee);
    auto const tokens = lptAMMBalance * (lptAMMBalance + ae * (f - 2)) /
        (lptAMMBalance * f - ae);
    if (tokens <= 0)
        return {tecAMM_FAILED, STAmount{}};
    auto const amountWithdraw = toSTAmount(amount.issue(), tokens / ePrice);
    if (amount == beast::zero || amountWithdraw >= amount)
    {
        TER result;
        STAmount newLPTokenBalance;
        bool withdrawAll =
            ctx_.tx[sfFlags] & (tfWithdrawAll | tfOneAssetWithdrawAll);
        std::tie(result, newLPTokenBalance, std::ignore, std::ignore) =
            withdraw(
                view,
                ammAccount,
                account_,
                ammSle,
                amountBalance,
                amountWithdraw,
                std::nullopt,
                lptAMMBalance,
                toSTAmount(lptAMMBalance.issue(), tokens),
                tfee,
                ctx_.journal,
                ctx_.tx,
                withdrawAll);

        return {result, newLPTokenBalance};
    }

    return {tecAMM_FAILED, STAmount{}};
}

}  // namespace ripple
