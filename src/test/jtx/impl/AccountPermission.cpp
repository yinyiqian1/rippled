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

#include <test/jtx/AccountPermission.h>
#include <xrpld/app/misc/AMMUtils.h>
#include <xrpl/protocol/AMMCore.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

namespace ripple {
namespace test {
namespace jtx {

namespace account_permission {

Json::Value
accountPermissionSet(
    jtx::Account const& account,
    jtx::Account const& authorize,
    std::list<std::string> const& permissions)
{
    Json::Value jv;
    jv[jss::TransactionType] = jss::AccountPermissionSet;
    jv[jss::Account] = account.human();
    jv[jss::Authorize] = authorize.human();
    Json::Value permissionsJson(Json::arrayValue);
    for (auto const& permission : permissions)
    {
        Json::Value permissionValue;
        permissionValue[jss::PermissionValue] = permission;
        Json::Value permissionObj;
        permissionObj[jss::Permission] = permissionValue;
        permissionsJson.append(permissionObj);
    }

    jv[jss::Permissions] = permissionsJson;

    return jv;
}

Json::Value
ledgerEntry(
    jtx::Env& env,
    jtx::Account const& account,
    jtx::Account const& authorize)
{
    Json::Value jvParams;
    jvParams[jss::ledger_index] = jss::validated;
    jvParams[jss::account_permission][jss::account] = account.human();
    jvParams[jss::account_permission][jss::authorize] = authorize.human();
    return env.rpc("json", "ledger_entry", to_string(jvParams));
}

Json::Value
ammCreate(
    jtx::Account const& account,
    STAmount const& amount1,
    STAmount const& amount2,
    std::uint32_t tfee,
    std::uint32_t fee,
    std::optional<jtx::Account> const& onBehalfOf)
{
    Json::Value jv;
    jv[jss::TransactionType] = jss::AMMCreate;
    jv[jss::Amount] = amount1.getJson(JsonOptions::none);
    jv[jss::Amount2] = amount2.getJson(JsonOptions::none);
    jv[jss::Account] = account.human();
    jv[jss::TradingFee] = tfee;
    jv[jss::Fee] = fee;
    if (onBehalfOf)
        jv[jss::OnBehalfOf] = onBehalfOf->human();

    return jv;
}

bool
ammBalances(
    jtx::Env& env,
    STAmount const& amount1,
    STAmount const& amount2,
    IOUAmount const& lpt)
{
    auto const asset1 = amount1.issue();
    auto const asset2 = amount2.issue();
    auto const amm = env.current()->read(keylet::amm(asset1, asset2));
    if (!amm)
        return false;
    auto const ammAccountID = amm->getAccountID(sfAccount);
    auto const [asset1Balance, asset2Balance] = ammPoolHolds(
        *env.current(),
        ammAccountID,
        asset1,
        asset2,
        FreezeHandling::fhIGNORE_FREEZE,
        env.journal);
    auto const lptBalance = amm->getFieldAmount(sfLPTokenBalance);
    auto const lptIssue =
        ripple::ammLPTIssue(asset1.currency, asset2.currency, ammAccountID);
    return amount1 == asset1Balance && amount2 == asset2Balance &&
        lptBalance == STAmount{lpt, lptIssue};
}

bool
holdLPTokens(
    jtx::Env& env,
    Issue const& asset1,
    Issue const& asset2,
    AccountID const& account,
    IOUAmount const& lpt)
{
    auto const amm = env.current()->read(keylet::amm(asset1, asset2));
    if (!amm)
        return false;
    auto const lptBalance =
        ammLPHolds(*env.current(), *amm, account, env.journal);
    auto const lptIssue = ripple::ammLPTIssue(
        asset1.currency, asset2.currency, amm->getAccountID(sfAccount));
    return lptBalance == STAmount{lpt, lptIssue};
}

Json::Value
ammDeposit(
    jtx::Account const& account,
    STAmount const& amount1,
    STAmount const& amount2,
    std::uint32_t fee,
    std::optional<std::uint32_t> const& flags,
    std::optional<jtx::Account> const& onBehalfOf)
{
    Json::Value jv;
    jv[jss::TransactionType] = jss::AMMDeposit;
    jv[jss::Amount] = amount1.getJson(JsonOptions::none);
    jv[jss::Amount2] = amount2.getJson(JsonOptions::none);
    jv[jss::Asset] = to_json(amount1.issue());
    jv[jss::Asset2] = to_json(amount2.issue());
    jv[jss::Account] = account.human();
    jv[jss::Fee] = fee;
    if (flags)
        jv[jss::Flags] = *flags;
    if (onBehalfOf)
        jv[jss::OnBehalfOf] = onBehalfOf->human();

    return jv;
}

}  // namespace account_permission
}  // namespace jtx
}  // namespace test
}  // namespace ripple
