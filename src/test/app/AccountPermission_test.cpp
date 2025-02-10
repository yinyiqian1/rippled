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
#include <test/jtx.h>
#include <test/jtx/AMM.h>
#include <test/jtx/AMMTest.h>
#include <test/jtx/AccountPermission.h>
#include <test/jtx/Oracle.h>
#include <test/jtx/xchain_bridge.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/jss.h>
#include <chrono>
namespace ripple {
namespace test {
class AccountPermission_test : public beast::unit_test::suite
{
    void
    testFeatureDisabled(FeatureBitset features)
    {
        testcase("test featureAccountPermission is not enabled");
        using namespace jtx;
        if (!features[featureAccountPermission])
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(1000000), gw, alice);
            env.close();

            env(account_permission::accountPermissionSet(
                    gw, alice, {"Payment"}),
                ter(temDISABLED));
        }
    }

    void
    testInvalidRequest(FeatureBitset features)
    {
        testcase("test invalid request");
        using namespace jtx;

        Env env(*this, features);
        Account gw{"gateway"};
        Account alice{"alice"};
        env.fund(XRP(100000), gw, alice);
        env.close();

        // when permissions size exceeds the limit 10, should return
        // temARRAY_TOO_LARGE.
        {
            env(account_permission::accountPermissionSet(
                    gw,
                    alice,
                    {"Payment",
                     "EscrowCreate",
                     "EscrowFinish",
                     "EscrowCancel",
                     "CheckCreate",
                     "CheckCash",
                     "CheckCancel",
                     "DepositPreauth",
                     "TrustSet",
                     "NFTokenMint",
                     "NFTokenBurn"}),
                ter(temARRAY_TOO_LARGE));
        }

        // when provided permissions contains some permission which does not
        // exists.
        {
            try
            {
                env(account_permission::accountPermissionSet(
                    gw, alice, {"Payment1"}));
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(
                    e.what() ==
                    std::string("invalidParamsError at "
                                "'tx_json.Permissions.[0].Permission'. Field "
                                "'tx_json.Permissions.[0].Permission."
                                "PermissionValue' has invalid data."));
            }
        }

        // when provided permissions contains duplicate values, should return
        // temMALFORMED.
        {
            env(account_permission::accountPermissionSet(
                    gw,
                    alice,
                    {"Payment",
                     "EscrowCreate",
                     "EscrowFinish",
                     "TrustlineAuthorize",
                     "CheckCreate",
                     "TrustlineAuthorize"}),
                ter(temMALFORMED));
        }

        // when authorizing account which does not exist, should return
        // terNO_ACCOUNT.
        {
            env(account_permission::accountPermissionSet(
                    gw, Account("unknown"), {"Payment"}),
                ter(terNO_ACCOUNT));
        }

        // for security reasons, AccountSet, SetRegularKey, SignerListSet,
        // AccountPermissionSet are prohibited to be delegated to other accounts
        {
            auto testProhibitedTrans = [&](std::string const& permission) {
                try
                {
                    env(account_permission::accountPermissionSet(
                        gw, alice, {"SetRegularKey"}));
                }
                catch (std::exception const& e)
                {
                    BEAST_EXPECT(
                        e.what() ==
                        std::string(
                            "invalidParamsError at "
                            "'tx_json.Permissions.[0].Permission'. Field "
                            "'tx_json.Permissions.[0].Permission."
                            "PermissionValue' has invalid data."));
                }
            };

            testProhibitedTrans("SetRegularKey");
            testProhibitedTrans("AccountSet");
            testProhibitedTrans("SignerListSet");
            testProhibitedTrans("AccountPermissionSet");
        }
    }

    void
    testPermissionCRUD(FeatureBitset features)
    {
        testcase("test valid request creating, updating, deleting permissions");
        using namespace jtx;

        Env env(*this, features);
        Account gw{"gateway"};
        Account alice{"alice"};
        env.fund(XRP(100000), gw, alice);
        env.close();

        auto const permissions = std::list<std::string>{
            "Payment",
            "EscrowCreate",
            "EscrowFinish",
            "TrustlineAuthorize",
            "CheckCreate"};
        env(account_permission::accountPermissionSet(gw, alice, permissions));
        env.close();

        // this lambda function is used to error message when the user tries to
        // get ledger entry with invalid parameters.
        auto testInvalidParams =
            [&](std::optional<std::string> const& account,
                std::optional<std::string> const& authorize) -> std::string {
            Json::Value jvParams;
            std::string error;
            jvParams[jss::ledger_index] = jss::validated;
            if (account)
                jvParams[jss::account_permission][jss::account] = *account;
            if (authorize)
                jvParams[jss::account_permission][jss::authorize] = *authorize;
            auto const& response =
                env.rpc("json", "ledger_entry", to_string(jvParams));
            if (response[jss::result].isMember(jss::error))
                error = response[jss::result][jss::error].asString();
            return error;
        };

        // get ledger entry with invalid parameters should return error.
        BEAST_EXPECT(
            testInvalidParams(std::nullopt, alice.human()) ==
            "malformedRequest");
        BEAST_EXPECT(
            testInvalidParams(gw.human(), std::nullopt) == "malformedRequest");
        BEAST_EXPECT(
            testInvalidParams("-", alice.human()) == "malformedAccount");
        BEAST_EXPECT(
            testInvalidParams(gw.human(), "-") == "malformedAuthorize");

        // this lambda function is used to compare the json value of ledger
        // entry response with the given list of permission strings.
        auto comparePermissions = [&](Json::Value const& jle,
                                      std::list<std::string> const& permissions,
                                      Account const& account,
                                      Account const& authorize) {
            BEAST_EXPECT(
                !jle[jss::result].isMember(jss::error) &&
                jle[jss::result].isMember(jss::node));
            BEAST_EXPECT(
                jle[jss::result][jss::node]["LedgerEntryType"] ==
                jss::AccountPermission);
            BEAST_EXPECT(
                jle[jss::result][jss::node][jss::Account] == account.human());
            BEAST_EXPECT(
                jle[jss::result][jss::node][jss::Authorize] ==
                authorize.human());

            auto const& jPermissions =
                jle[jss::result][jss::node][jss::Permissions];
            unsigned i = 0;
            for (auto const& permission : permissions)
            {
                auto const granularVal =
                    Permission::getInstance().getGranularValue(permission);
                if (granularVal)
                    BEAST_EXPECT(
                        jPermissions[i][jss::Permission]
                                    [jss::PermissionValue] == *granularVal);
                else
                {
                    auto const transVal =
                        TxFormats::getInstance().findTypeByName(permission);
                    BEAST_EXPECT(
                        jPermissions[i][jss::Permission]
                                    [jss::PermissionValue] == transVal + 1);
                }
                i++;
            }
        };

        // get ledger entry with valid parameter
        comparePermissions(
            account_permission::ledgerEntry(env, gw, alice),
            permissions,
            gw,
            alice);

        // gw update permission
        auto const newPermissions = std::list<std::string>{
            "Payment", "AMMCreate", "AMMDeposit", "AMMWithdraw"};
        env(account_permission::accountPermissionSet(
            gw, alice, newPermissions));
        env.close();

        // get ledger entry again, permissions should be updated to
        // newPermissions
        comparePermissions(
            account_permission::ledgerEntry(env, gw, alice),
            newPermissions,
            gw,
            alice);

        // gw delete all permissions delegated to alice, this will delete the
        // ledger entry
        env(account_permission::accountPermissionSet(gw, alice, {}));
        env.close();
        auto const jle = account_permission::ledgerEntry(env, gw, alice);
        BEAST_EXPECT(jle[jss::result][jss::error] == "entryNotFound");

        // alice can delegate permissions to gw as well
        env(account_permission::accountPermissionSet(alice, gw, permissions));
        env.close();
        comparePermissions(
            account_permission::ledgerEntry(env, alice, gw),
            permissions,
            alice,
            gw);
        auto const response = account_permission::ledgerEntry(env, gw, alice);
        // alice is not delegated any permissions by gw, should return
        // entryNotFound
        BEAST_EXPECT(response[jss::result][jss::error] == "entryNotFound");
    }

    void
    testAMM(FeatureBitset features)
    {
        testcase(
            "test AMMCreate, AMMDeposit, AMMWithdraw, AMMClawback, AMMVote, "
            "AMMDelete and AMMBid");
        using namespace jtx;

        // test AMMCreate, AMMDeposit, AMMWithdraw, AMMClawback
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            Account bob{"bob"};
            env.fund(XRP(1000000000), gw, alice, bob);
            env.close();

            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            auto const USD = gw["USD"];
            env.trust(USD(10000), alice);
            env(pay(gw, alice, USD(3000)));
            env.trust(USD(10000), bob);
            env(pay(gw, bob, USD(3000)));
            env.close();

            // alice delegates AMMCreate, AMMDeposit, AMMWithdraw to bob
            env(account_permission::accountPermissionSet(
                alice, bob, {"AMMCreate", "AMMDeposit", "AMMWithdraw"}));
            env.close();

            auto aliceXrpBalance = env.balance(alice, XRP);
            auto bobXrpBalance = env.balance(bob, XRP);

            AMM amm(env, bob, USD(1000), XRP(2000), alice, ter(tesSUCCESS));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(1000), XRP(2000), IOUAmount{1414213562373095, -9}));

            // bob sends the AMMCreate on behalf of alice, so alice holds all
            // the lptokens, bob holds 0.
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{1414213562373095, -9}));
            BEAST_EXPECT(amm.expectLPTokens(bob, IOUAmount(0)));

            // alice initially has 3000USD, 1000USD is deducted to create the
            // AMM pool, 2000USD left
            env.require(balance(alice, USD(2000)));
            env.require(balance(bob, USD(3000)));

            // alice spent 2000XRP to create the AMM
            env.require(balance(alice, aliceXrpBalance - XRP(2000)));
            // bob sent the transaction, bob pays the fee
            env.require(balance(bob, bobXrpBalance - XRP(50)));

            // update alice and bob balance variables
            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // bob deposit 1000USD/2000XRP on behalf of alice
            amm.deposit(
                bob,
                USD(1000),
                XRP(2000),
                std::nullopt,
                std::nullopt,
                ter(tesSUCCESS),
                alice);
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(2000), XRP(4000), IOUAmount{2828427124746190, -9}));

            // alice holds all the lptokens, and bob has 0 in the pool
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{2828427124746190, -9}));
            BEAST_EXPECT(amm.expectLPTokens(bob, IOUAmount(0)));

            // alice spent another 1000USD and 2000XRP to deposit
            env.require(balance(alice, USD(1000)));
            env.require(balance(bob, USD(3000)));
            env.require(balance(alice, aliceXrpBalance - XRP(2000)));
            // bob sent the transaction, bob pays another 10 drop XRP fee
            env.require(balance(bob, bobXrpBalance - drops(10)));

            // update alice and bob balance variables
            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // bob can deposit for himself
            amm.deposit(bob, USD(1000), XRP(2000));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(3000), XRP(6000), IOUAmount{4242640687119285, -9}));
            ;
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{2828427124746190, -9}));
            BEAST_EXPECT(
                amm.expectLPTokens(bob, IOUAmount{1414213562373095, -9}));

            env.require(balance(alice, USD(1000)));
            env.require(balance(bob, USD(2000)));

            // alice's XRP balance keeps the same

            env.require(balance(alice, aliceXrpBalance));
            // bob spent 2000XRP to deposit and also pays 10 drops fee
            env.require(balance(bob, bobXrpBalance - XRP(2000) - drops(10)));

            // update alice and bob balance variables
            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // bob withdraw 1000USD/2000XRP on behalf of alice
            amm.withdraw(
                bob,
                USD(1000),
                XRP(2000),
                std::nullopt,
                ter(tesSUCCESS),
                alice);
            env.close();

            // the 1000USD/2000XRP is withdrawn from alice, so alice's
            // lptoken is deducted by half, bob's lptoken balance remains the
            // same.
            BEAST_EXPECT(amm.expectBalances(
                USD(2000), XRP(4000), IOUAmount{2828427124746190, -9}));
            ;
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{1414213562373095, -9}));
            BEAST_EXPECT(
                amm.expectLPTokens(bob, IOUAmount{1414213562373095, -9}));

            // alice gets 1000 USD back so she has 2000 USD now
            env.require(balance(alice, USD(2000)));
            env.require(balance(bob, USD(2000)));

            // alice gets 2000 XRP back
            env.require(balance(alice, aliceXrpBalance + XRP(2000)));
            // bob pays 10 drops fee
            env.require(balance(bob, bobXrpBalance - drops(10)));

            // update alice and bob balance variables
            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // bob can withdraw 1000USD/2000XRP for himself
            amm.withdraw(bob, USD(1000), XRP(2000));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(1000), XRP(2000), IOUAmount{1414213562373095, -9}));
            ;
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{1414213562373095, -9}));
            BEAST_EXPECT(amm.expectLPTokens(bob, IOUAmount(0)));
            env.require(balance(alice, USD(2000)));
            env.require(balance(bob, USD(3000)));
            env.require(balance(alice, aliceXrpBalance));
            // bob gets 2000XRP back and pays 10 drops fee
            env.require(balance(bob, bobXrpBalance + XRP(2000) - drops(10)));

            // alice can not AMMClawback from herself on behalf of gw
            // todo: check here
            // env(amm::ammClawback(
            //         alice, alice, USD, XRP, USD(1000), gw),
            //     ter(tecNO_PERMISSION));
            // env.close();

            // gw give permission to alice for AMMClawback transaction
            env(account_permission::accountPermissionSet(
                gw, alice, {"AMMClawback"}));
            env.close();

            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // now alice can AMMClawback from herself onbehalf of gw
            env(amm::ammClawback(alice, alice, USD, XRP, USD(500), gw));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(500), XRP(1000), IOUAmount{7071067811865475, -10}));
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{7071067811865475, -10}));
            env.require(balance(alice, USD(2000)));
            // alice gets 1000 XRP back and pays 10 drops fee as the sender
            env.require(
                balance(alice, aliceXrpBalance + XRP(1000) - drops(10)));

            // bob deposit for himself
            amm.deposit(bob, USD(1000), XRP(2000));
            env.close();

            // there's some rounding happening
            BEAST_EXPECT(amm.expectBalances(
                STAmount{USD, UINT64_C(1499999999999999), -12},
                XRP(3000),
                IOUAmount{2121320343559642, -9}));
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{7071067811865475, -10}));
            BEAST_EXPECT(
                amm.expectLPTokens(bob, IOUAmount{1414213562373094, -9}));
            env.require(balance(alice, USD(2000)));
            env.require(
                balance(bob, STAmount{USD, UINT64_C(2000000000000001), -12}));
            env.require(balance(bob, bobXrpBalance - XRP(2000) - drops(10)));

            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // alice AMMClawback all bob's USD on behalf of gw
            env(amm::ammClawback(alice, bob, USD, XRP, std::nullopt, gw));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                STAmount{USD, UINT64_C(5000000000000001), -13},
                XRP(1000),
                IOUAmount{7071067811865480, -10}));
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{7071067811865475, -10}));
            BEAST_EXPECT(amm.expectLPTokens(bob, IOUAmount(0)));
            env.require(balance(alice, USD(2000)));
            env.require(
                balance(bob, STAmount{USD, UINT64_C(2000000000000001), -12}));
            env.require(balance(alice, aliceXrpBalance - drops(10)));
            env.require(balance(bob, bobXrpBalance + XRP(2000)));

            // alice AMMClawback all alice's USD on behalf of gw, the amm should
            // be empty and get deleted todo: ammclawback all, will reveal AMM
            // bug, 7071067811865480 != 7071067811865475 env(amm::ammClawback(
            //         alice, alice, USD, XRP, USD(2000), gw),
            //     ter(tesSUCCESS));
            // env.close();
            // BEAST_EXPECT(!amm.ammExists());
        }

        // test AMMVote
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            Account bob{"bob"};
            env.fund(XRP(1000000000), gw, alice, bob);
            env.close();

            auto const USD = gw["USD"];
            env.trust(USD(10000), alice);
            env(pay(gw, alice, USD(3000)));
            env.trust(USD(10000), bob);
            env(pay(gw, bob, USD(3000)));
            env.close();

            // alice delegates AMMVote to bob
            env(account_permission::accountPermissionSet(
                alice, bob, {"AMMVote"}));
            env.close();

            AMM amm(env, alice, USD(1000), XRP(2000), ter(tesSUCCESS));
            env.close();

            auto aliceXrpBalance = env.balance(alice, XRP);
            auto bobXrpBalance = env.balance(bob, XRP);

            BEAST_EXPECT(amm.expectTradingFee(0));
            amm.vote(alice, 100);
            env.close();
            BEAST_EXPECT(amm.expectTradingFee(100));
            // alice is the sender who pays the fee
            env.require(balance(alice, aliceXrpBalance - drops(10)));
            env.require(balance(bob, bobXrpBalance));

            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // bob vote onbehalf of alice
            amm.vote(
                bob,
                500,
                std::nullopt,
                std::nullopt,
                std::nullopt,
                ter(tesSUCCESS),
                alice);
            env.close();
            BEAST_EXPECT(amm.expectTradingFee(500));
            // bob is the sender who pays the fee
            env.require(balance(alice, aliceXrpBalance));
            env.require(balance(bob, bobXrpBalance - drops(10)));

            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);

            // bob vote again onbehalf of alice
            amm.vote(
                bob,
                1000,
                std::nullopt,
                std::nullopt,
                std::nullopt,
                ter(tesSUCCESS),
                alice);
            env.close();
            BEAST_EXPECT(amm.expectTradingFee(1000));
            env.require(balance(alice, aliceXrpBalance));
            env.require(balance(bob, bobXrpBalance - drops(10)));
        }

        // test AMMDelete
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(1000000000), gw, alice);
            env.close();

            auto const USD = gw["USD"];
            env.trust(USD(10000), alice);
            env(pay(gw, alice, USD(3000)));
            env.close();

            // gw delegates AMMDelete to alice
            env(account_permission::accountPermissionSet(
                gw, alice, {"AMMDelete"}));
            env.close();

            AMM amm(env, gw, USD(1000), XRP(2000), ter(tesSUCCESS));
            env.close();
            // create a lot of trust lines with the lptoken issuer
            for (auto i = 0; i < maxDeletableAMMTrustLines * 2 + 10; ++i)
            {
                Account const a{std::to_string(i)};
                env.fund(XRP(1'000), a);
                env(trust(a, STAmount{amm.lptIssue(), 10'000}));
                env.close();
            }

            // there are lots of trustlines so the amm still exists
            amm.withdrawAll(gw);
            BEAST_EXPECT(amm.ammExists());

            auto gwXrpBalance = env.balance(gw, XRP);
            auto aliceXrpBalance = env.balance(alice, XRP);

            // gw delete amm, but at most 512 trustlines are deleted at once, so
            // it's incomplete
            amm.ammDelete(gw, ter(tecINCOMPLETE));
            BEAST_EXPECT(amm.ammExists());
            // alice is the sender who pays the fee
            env.require(balance(gw, gwXrpBalance - drops(10)));
            env.require(balance(alice, aliceXrpBalance));

            gwXrpBalance = env.balance(gw, XRP);
            aliceXrpBalance = env.balance(alice, XRP);

            // alice delete amm onbehalf of gw
            amm.ammDelete(alice, ter(tesSUCCESS), gw);
            BEAST_EXPECT(!amm.ammExists());
            BEAST_EXPECT(!env.le(keylet::ownerDir(amm.ammAccount())));
            env.require(balance(gw, gwXrpBalance));
            // alice is the sender who pays the fee
            env.require(balance(alice, aliceXrpBalance - drops(10)));

            // Try redundant delete
            amm.ammDelete(alice, ter(terNO_AMM));
        }

        // test AMMBid
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(XRP(1000000000), gw, alice, bob, carol);
            env.close();

            auto const USD = gw["USD"];
            env.trust(USD(10000), alice);
            env(pay(gw, alice, USD(3000)));
            env.close();

            // alice delegates AMMBid to bob
            env(account_permission::accountPermissionSet(
                alice, bob, {"AMMBid"}));
            env.close();

            AMM amm(env, gw, USD(1000), XRP(2000), ter(tesSUCCESS));
            env.close();

            auto aliceXrpBalance = env.balance(alice, XRP);
            auto bobXrpBalance = env.balance(bob, XRP);

            env(amm.bid(
                {.account = gw, .bidMin = 110, .authAccounts = {alice}}));
            BEAST_EXPECT(amm.expectAuctionSlot(0, 0, IOUAmount{110}));
            BEAST_EXPECT(amm.expectAuctionSlot({alice}));

            amm.deposit(alice, 1'000'000);

            // because bob is not lp, can not bid
            env(amm.bid({.account = bob, .authAccounts = {bob}}),
                ter(tecAMM_INVALID_TOKENS));

            // but bob can bid onbehalf of alice who is the lp
            env(amm.bid(
                {.account = bob,
                 .onBehalfOf = alice,
                 .authAccounts = {alice, bob, carol}}));
            env.close();
            BEAST_EXPECT(amm.expectAuctionSlot(0, 0, IOUAmount(1155, -1)));
            BEAST_EXPECT(amm.expectAuctionSlot({alice, bob, carol}));
        }
    }

    void
    testCheck(FeatureBitset features)
    {
        testcase("test CheckCreate, CheckCash and CheckCancel");
        using namespace jtx;

        // test create and cash check of XRP on behalf of another account
        {
            Env env(*this, features);
            XRPAmount const baseFee{env.current()->fees().base};
            STAmount const startBalance{XRP(1000000).value()};

            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(startBalance, alice, bob, carol);
            env.close();

            // bob can not write a check to himself
            env(check::create(bob, bob, XRP(10)), ter(temREDUNDANT));
            env.close();
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 0);

            // alice delegates CheckCreate to bob
            env(account_permission::accountPermissionSet(
                alice, bob, {"CheckCreate"}));
            env.close();

            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance));

            // now bob send a check on behalf of alice to alice,
            // this should fail as well
            env(check::create(bob, alice, XRP(10)),
                onBehalfOf(alice),
                ter(temREDUNDANT));
            env.close();
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance));
            env.require(balance(carol, startBalance));

            // now bob send a check on behalf of alice to bob himself,
            // this should succeed because it's alice->bob
            uint256 const aliceToBob = keylet::check(alice, env.seq(alice)).key;
            env(check::create(bob, bob, XRP(10)), onBehalfOf(alice));
            env.close();
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 1);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 1);
            // alice owns the account permission and check
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance - drops(baseFee)));
            env.require(balance(carol, startBalance));

            // bob send a check on behalf of alice to carol, the check is
            // actually alice->carol
            uint256 const aliceToCarol =
                keylet::check(alice, env.seq(alice)).key;
            env(check::create(bob, carol, XRP(100)), onBehalfOf(alice));
            env.close();
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 2);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 1);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 1);
            // alice owns the account permission and 2 checks
            BEAST_EXPECT(ownerCount(env, alice) == 3);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            BEAST_EXPECT(ownerCount(env, carol) == 0);
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance - drops(baseFee * 2)));
            env.require(balance(carol, startBalance));

            // bob cash the check
            env(check::cash(bob, aliceToBob, XRP(10)));
            env.close();
            env.require(
                balance(alice, startBalance - XRP(10) - drops(baseFee)));
            env.require(
                balance(bob, startBalance + XRP(10) - drops(baseFee * 3)));
            env.require(balance(carol, startBalance));
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 1);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 1);
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            BEAST_EXPECT(ownerCount(env, carol) == 0);

            env(check::cash(bob, aliceToCarol, XRP(10)), ter(tecNO_PERMISSION));
            env.require(
                balance(bob, startBalance + XRP(10) - drops(baseFee * 4)));

            // carol delegates CheckCash to bob
            env(account_permission::accountPermissionSet(
                carol, bob, {"CheckCash"}));
            env.close();
            env.require(
                balance(bob, startBalance + XRP(10) - drops(baseFee * 4)));
            env.require(balance(carol, startBalance - drops(baseFee)));
            BEAST_EXPECT(ownerCount(env, carol) == 1);

            // bob cash the check on behalf of carol
            env(check::cash(bob, aliceToCarol, XRP(100), carol));
            env.close();

            env.require(
                balance(alice, startBalance - XRP(110) - drops(baseFee)));
            env.require(
                balance(bob, startBalance + XRP(10) - drops(baseFee * 5)));
            env.require(
                balance(carol, startBalance + XRP(100) - drops(baseFee)));
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 0);
            BEAST_EXPECT(ownerCount(env, alice) == 1);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            BEAST_EXPECT(ownerCount(env, carol) == 1);
        }

        // test create/cash/cancel check of USD on behalf of another account
        {
            Env env(*this, features);
            XRPAmount const baseFee{env.current()->fees().base};
            STAmount const startBalance{XRP(1000000).value()};

            Account gw{"gw"};
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(startBalance, gw, alice, bob, carol);
            env.close();

            auto const USD = gw["USD"];

            // alice give CheckCreate permission to bob
            env(account_permission::accountPermissionSet(
                alice, bob, {"CheckCreate"}));
            env.close();
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance));

            // bob writes 10USD check on behalf of alice when alice does not
            // have USD
            uint256 const aliceToCarol =
                keylet::check(alice, env.seq(alice)).key;
            env(check::create(bob, carol, USD(10)), onBehalfOf(alice));
            env.close();
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance - drops(baseFee)));
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 1);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 1);
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            BEAST_EXPECT(ownerCount(env, carol) == 0);

            // carol give CheckCash permission to bob
            env(account_permission::accountPermissionSet(
                carol, bob, {"CheckCash"}));
            env.close();
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance - drops(baseFee)));
            env.require(balance(carol, startBalance - drops(baseFee)));
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            BEAST_EXPECT(ownerCount(env, carol) == 1);

            // bob cash the check on behalf of carol should fail bacause alice
            // does not have USD
            env(check::cash(bob, aliceToCarol, USD(10), carol),
                ter(tecPATH_PARTIAL));
            env.close();
            env.require(balance(alice, startBalance - drops(baseFee)));
            env.require(balance(bob, startBalance - drops(2 * baseFee)));
            env.require(balance(carol, startBalance - drops(baseFee)));
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            BEAST_EXPECT(ownerCount(env, carol) == 1);

            // alice does not have enough USD
            env(trust(alice, USD(100)));
            env(pay(gw, alice, USD(9.5)));
            env.close();
            env.require(balance(alice, startBalance - drops(2 * baseFee)));
            env(check::cash(bob, aliceToCarol, USD(10), carol),
                ter(tecPATH_PARTIAL));
            env.close();
            env.require(balance(bob, startBalance - drops(3 * baseFee)));
            env.require(balance(alice, USD(9.5)));
            BEAST_EXPECT(ownerCount(env, alice) == 3);

            // now alice have enough USD
            env(pay(gw, alice, USD(0.5)));
            env.close();

            // bob cash 9.9 USD on behalf of carol
            env(check::cash(bob, aliceToCarol, USD(9.9), carol));
            env.close();
            env.require(balance(alice, startBalance - drops(2 * baseFee)));
            env.require(balance(bob, startBalance - drops(4 * baseFee)));
            env.require(balance(carol, startBalance - drops(baseFee)));
            env.require(balance(alice, USD(0.1)));
            env.require(balance(carol, USD(9.9)));
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 0);
            // cashing the check automatically creats a trustline for carol
            BEAST_EXPECT(ownerCount(env, carol) == 2);
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 0);

            // bob trying to cash the same check on behalf of carol should fail
            env(check::cash(bob, aliceToCarol, USD(10), carol),
                ter(tecNO_ENTRY));
            env.require(balance(bob, startBalance - drops(5 * baseFee)));

            // carol does not have permission yet.
            env(check::create(carol, alice, USD(10)),
                onBehalfOf(bob),
                ter(tecNO_PERMISSION));
            // fail again
            env(check::create(carol, alice, USD(10)),
                onBehalfOf(bob),
                ter(tecNO_PERMISSION));
            env.require(balance(carol, startBalance - drops(3 * baseFee)));

            // bob allows carol to send CheckCreate on behalf of himself
            env(account_permission::accountPermissionSet(
                bob, carol, {"CheckCreate"}));
            env.close();
            env.require(balance(bob, startBalance - drops(6 * baseFee)));

            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 1);
            BEAST_EXPECT(ownerCount(env, carol) == 2);

            // carol writes two checks on behalf of bob to alice
            uint256 const checkId1 = keylet::check(bob, env.seq(bob)).key;
            env(check::create(carol, alice, USD(20)), onBehalfOf(bob));
            uint256 const checkId2 = keylet::check(bob, env.seq(bob)).key;
            env(check::create(carol, alice, USD(10)), onBehalfOf(bob));
            env.close();
            env.require(balance(alice, startBalance - drops(2 * baseFee)));
            env.require(balance(bob, startBalance - drops(6 * baseFee)));
            env.require(balance(carol, startBalance - drops(5 * baseFee)));
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 3);
            BEAST_EXPECT(ownerCount(env, carol) == 2);
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 2);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 2);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 0);

            // alice allows bob to cash check on behalf of herself
            env(account_permission::accountPermissionSet(
                alice, bob, {"CheckCash"}));
            env.close();
            env.require(balance(alice, startBalance - drops(3 * baseFee)));
            // alice already owns AccountPermission object for "alice
            // delegating bob"
            BEAST_EXPECT(ownerCount(env, alice) == 2);

            // alice allows bob to cancel check on behalf of herself.
            env(account_permission::accountPermissionSet(
                alice, bob, {"CheckCash", "CheckCancel"}));
            env.close();
            env.require(balance(alice, startBalance - drops(4 * baseFee)));
            BEAST_EXPECT(ownerCount(env, alice) == 2);

            env(trust(bob, USD(10)));
            env(pay(gw, bob, USD(10)));
            env.close();
            env.require(balance(bob, startBalance - drops(7 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 4);

            // bob cash check2 on behalf of alice
            env(check::cash(bob, checkId2, USD(10), alice));
            env.close();
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 1);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 1);
            BEAST_EXPECT(check::checksOnAccount(env, carol).size() == 0);
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 3);
            BEAST_EXPECT(ownerCount(env, carol) == 2);
            env.require(balance(alice, startBalance - drops(4 * baseFee)));
            env.require(balance(bob, startBalance - drops(8 * baseFee)));
            env.require(balance(carol, startBalance - drops(5 * baseFee)));
            env.require(balance(alice, USD(10.1)));
            env.require(balance(bob, USD(0)));

            // bob cancel check1 on behalf of alice
            env(check::cancel(bob, checkId1, alice));
            env.close();
            BEAST_EXPECT(check::checksOnAccount(env, alice).size() == 0);
            BEAST_EXPECT(check::checksOnAccount(env, bob).size() == 0);
            BEAST_EXPECT(ownerCount(env, alice) == 2);
            BEAST_EXPECT(ownerCount(env, bob) == 2);
        }
    }

    void
    testClawback(FeatureBitset features)
    {
        testcase("test Clawback");
        using namespace jtx;

        Env env(*this, features);
        XRPAmount const baseFee{env.current()->fees().base};
        STAmount const startBalance{XRP(1000000).value()};

        Account gw{"gw"};
        Account alice{"alice"};
        Account bob{"bob"};
        env.fund(startBalance, gw, alice, bob);
        env.close();

        // set asfAllowTrustLineClawback
        env(fset(gw, asfAllowTrustLineClawback));
        env(fset(alice, asfAllowTrustLineClawback));
        env.close();
        env.require(flags(gw, asfAllowTrustLineClawback));
        env.require(flags(alice, asfAllowTrustLineClawback));
        env.require(balance(gw, startBalance - drops(baseFee)));
        env.require(balance(alice, startBalance - drops(baseFee)));

        // gw issues bob 1000USD
        auto const USD = gw["USD"];
        env.trust(USD(10000), bob);
        env(pay(gw, bob, USD(1000)));
        env.close();
        env.require(balance(gw, startBalance - drops(2 * baseFee)));
        BEAST_EXPECT(ownerCount(env, bob) == 1);
        env.require(balance(bob, USD(1000)));

        // alice clawback from bob on behalf of gw should fail
        // because she does not have permission.
        env(claw(alice, bob["USD"](100)),
            onBehalfOf(gw),
            ter(tecNO_PERMISSION));
        env.close();
        env.require(balance(alice, startBalance - drops(2 * baseFee)));
        env.require(balance(bob, startBalance));
        env.require(balance(gw, startBalance - drops(2 * baseFee)));
        env.require(balance(bob, USD(1000)));

        // now gw give permission to alice
        env(account_permission::accountPermissionSet(gw, alice, {"Clawback"}));
        env.close();
        env.require(balance(alice, startBalance - drops(2 * baseFee)));
        env.require(balance(bob, startBalance));
        env.require(balance(gw, startBalance - drops(3 * baseFee)));
        BEAST_EXPECT(ownerCount(env, gw) == 1);
        BEAST_EXPECT(ownerCount(env, bob) == 1);

        // now alice can claw on behalf gw
        env(claw(alice, bob["USD"](100)), onBehalfOf(gw));
        env.close();
        env.require(balance(alice, startBalance - drops(3 * baseFee)));
        env.require(balance(bob, startBalance));
        env.require(balance(gw, startBalance - drops(3 * baseFee)));
        BEAST_EXPECT(ownerCount(env, gw) == 1);
        BEAST_EXPECT(ownerCount(env, bob) == 1);
        env.require(balance(bob, USD(900)));

        // gw claw another 200USD from bob by himself
        env(claw(gw, bob["USD"](200)));
        env.close();
        env.require(balance(alice, startBalance - drops(3 * baseFee)));
        env.require(balance(bob, startBalance));
        env.require(balance(gw, startBalance - drops(4 * baseFee)));
        BEAST_EXPECT(ownerCount(env, gw) == 1);
        BEAST_EXPECT(ownerCount(env, bob) == 1);
        env.require(balance(bob, USD(700)));

        // update limit
        env(trust(bob, USD(0), 0));
        env.close();
        env.require(balance(bob, startBalance - drops(baseFee)));

        // alice claw the remaining balance from bob on behalf gw
        env(claw(alice, bob["USD"](700)), onBehalfOf(gw));
        env.close();
        env.require(balance(alice, startBalance - drops(4 * baseFee)));
        env.require(balance(bob, startBalance - drops(baseFee)));
        env.require(balance(gw, startBalance - drops(4 * baseFee)));
        BEAST_EXPECT(ownerCount(env, gw) == 1);
        // the trustline got deleted
        BEAST_EXPECT(ownerCount(env, bob) == 0);
    }

    void
    testCrendentials(FeatureBitset features)
    {
        testcase("test crendentials");
        using namespace jtx;
        Account const subject{"subject"};

        {
            Env env(*this, features);
            Account alice{"alice"};
            Account issuer{"issuer"};
            Account subject{"subject"};
            env.fund(XRP(5'000), alice, issuer, subject);
            env.close();

            const char credType[] = "abcde";
            const char uri[] = "uri";
            auto const credKey =
                credentials::credentialKeylet(subject, issuer, credType);

            // create credential on behalf of another account
            {
                // alice creating credential on behalf of issuer is not
                // permitted
                env(credentials::create(subject, alice, credType),
                    credentials::uri(uri),
                    onBehalfOf(issuer),
                    ter(tecNO_PERMISSION));
                env.close();  // todo: remove this line will fail, the ledger
                              // object already exists

                env(account_permission::accountPermissionSet(
                    issuer, alice, {"CredentialCreate"}));
                env.close();
                BEAST_EXPECT(ownerCount(env, issuer) == 1);
                BEAST_EXPECT(ownerCount(env, alice) == 0);

                // alice creates credential on behalf of issuer successfully
                env(credentials::create(subject, alice, credType),
                    credentials::uri(uri),
                    onBehalfOf(issuer));
                env.close();
                BEAST_EXPECT(ownerCount(env, issuer) == 2);

                auto const sleCred = env.le(credKey);
                BEAST_EXPECT(sleCred);
                BEAST_EXPECT(sleCred->getAccountID(sfSubject) == subject.id());
                BEAST_EXPECT(sleCred->getAccountID(sfIssuer) == issuer.id());
                BEAST_EXPECT(!sleCred->getFieldU32(sfFlags));
                BEAST_EXPECT(
                    credentials::checkVL(sleCred, sfCredentialType, credType));
                BEAST_EXPECT(credentials::checkVL(sleCred, sfURI, uri));
            }

            // accept credential on behalf of another account
            {
                env(account_permission::accountPermissionSet(
                    subject, alice, {"CredentialAccept"}));
                env.close();
                BEAST_EXPECT(ownerCount(env, subject) == 1);
                BEAST_EXPECT(ownerCount(env, alice) == 0);

                // alice accept credential on behalf of subject
                env(credentials::accept(alice, issuer, credType),
                    onBehalfOf(subject));
                env.close();
                // owner of credential now is subject, not issuer
                BEAST_EXPECT(ownerCount(env, subject) == 2);
                BEAST_EXPECT(ownerCount(env, issuer) == 1);
                auto const sleCred = env.le(credKey);
                BEAST_EXPECT(sleCred);
                BEAST_EXPECT(sleCred->getAccountID(sfSubject) == subject.id());
                BEAST_EXPECT(sleCred->getAccountID(sfIssuer) == issuer.id());
                BEAST_EXPECT(sleCred->getFieldU32(sfFlags) == lsfAccepted);
                BEAST_EXPECT(
                    credentials::checkVL(sleCred, sfCredentialType, credType));
                BEAST_EXPECT(credentials::checkVL(sleCred, sfURI, uri));
            }

            // delete credential on behalf of another account
            {
                env(account_permission::accountPermissionSet(
                    subject, alice, {"CredentialDelete"}));
                env.close();
                BEAST_EXPECT(ownerCount(env, subject) == 2);
                BEAST_EXPECT(ownerCount(env, issuer) == 1);

                env(credentials::deleteCred(alice, subject, issuer, credType),
                    onBehalfOf(subject));
                env.close();
                BEAST_EXPECT(!env.le(credKey));
                BEAST_EXPECT(ownerCount(env, subject) == 1);
                BEAST_EXPECT(ownerCount(env, issuer) == 1);
            }

            // create and delete credential on behalf of issuer for the issuer
            // himself
            {
                env(account_permission::accountPermissionSet(
                    issuer, alice, {"CredentialCreate", "CredentialDelete"}));
                env.close();
                BEAST_EXPECT(ownerCount(env, issuer) == 1);

                env(credentials::create(issuer, alice, credType),
                    credentials::uri(uri),
                    onBehalfOf(issuer));
                env.close();
                BEAST_EXPECT(ownerCount(env, issuer) == 2);

                auto const credKey =
                    credentials::credentialKeylet(issuer, issuer, credType);

                auto sleCred = env.le(credKey);
                BEAST_EXPECT(sleCred);
                BEAST_EXPECT(sleCred->getAccountID(sfSubject) == issuer.id());
                BEAST_EXPECT(sleCred->getAccountID(sfIssuer) == issuer.id());
                BEAST_EXPECT(
                    credentials::checkVL(sleCred, sfCredentialType, credType));
                BEAST_EXPECT(credentials::checkVL(sleCred, sfURI, uri));
                BEAST_EXPECT(sleCred->getFieldU32(sfFlags) == lsfAccepted);

                env(credentials::deleteCred(alice, issuer, issuer, credType),
                    onBehalfOf(issuer));
                env.close();
                BEAST_EXPECT(!env.le(credKey));
                BEAST_EXPECT(ownerCount(env, issuer) == 1);
            }
        }
    }

    void
    testDepositPreauth(FeatureBitset features)
    {
        testcase("test DepositPreauth");
        using namespace jtx;

        {
            Env env(*this, features);
            XRPAmount const baseFee{env.current()->fees().base};
            STAmount const startBalance{XRP(1000000).value()};

            Account gw{"gw"};
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(startBalance, gw, alice, bob, carol);
            env.close();

            auto const USD = gw["USD"];
            env.trust(USD(10000), alice);
            env.trust(USD(10000), bob);
            env.trust(USD(10000), carol);
            env.close();

            env(pay(gw, alice, USD(1000)));
            env(pay(gw, bob, USD(1000)));
            env(pay(gw, carol, USD(1000)));
            env.close();
            env.require(balance(alice, startBalance));
            env.require(balance(bob, startBalance));
            env.require(balance(carol, startBalance));
            env.require(balance(alice, USD(1000)));
            env.require(balance(bob, USD(1000)));
            env.require(balance(carol, USD(1000)));
            BEAST_EXPECT(ownerCount(env, alice) == 1);
            BEAST_EXPECT(ownerCount(env, bob) == 1);
            BEAST_EXPECT(ownerCount(env, carol) == 1);

            // bob requiress authorization for deposits
            env(fset(bob, asfDepositAuth));
            env.close();
            env.require(balance(bob, startBalance - drops(baseFee)));

            // alice and carol can not pay bob
            env(pay(alice, bob, XRP(100)), ter(tecNO_PERMISSION));
            env(pay(alice, bob, USD(100)), ter(tecNO_PERMISSION));
            env(pay(carol, bob, XRP(100)), ter(tecNO_PERMISSION));
            env(pay(carol, bob, USD(100)), ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(alice, startBalance - drops(2 * baseFee)));
            env.require(balance(bob, startBalance - drops(baseFee)));
            env.require(balance(carol, startBalance - drops(2 * baseFee)));

            // bob preauthorizes carol for deposit
            env(deposit::auth(bob, carol));
            env.close();
            env.require(balance(bob, startBalance - drops(2 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 2);

            // carol can pay bob
            env(pay(carol, bob, XRP(100)));
            env(pay(carol, bob, USD(100)));
            // alice still can not pay
            env(pay(alice, bob, XRP(100)), ter(tecNO_PERMISSION));
            env(pay(alice, bob, USD(100)), ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(alice, startBalance - drops(4 * baseFee)));
            env.require(
                balance(bob, startBalance + XRP(100) - drops(2 * baseFee)));
            env.require(
                balance(carol, startBalance - XRP(100) - drops(4 * baseFee)));
            env.require(balance(alice, USD(1000)));
            env.require(balance(bob, USD(1100)));
            env.require(balance(carol, USD(900)));
            BEAST_EXPECT(ownerCount(env, alice) == 1);
            BEAST_EXPECT(ownerCount(env, bob) == 2);
            BEAST_EXPECT(ownerCount(env, carol) == 1);

            // bob give permission to carol to preauthorize other accounts for
            // deposit
            env(account_permission::accountPermissionSet(
                bob, carol, {"DepositPreauth"}));
            env.close();
            env.require(
                balance(bob, startBalance + XRP(100) - drops(3 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 3);
            BEAST_EXPECT(ownerCount(env, carol) == 1);

            // now carol send DepositPreauth on behalf of bob to allow alice to
            // deposit
            env(deposit::auth(carol, alice, bob));
            env.close();
            env.require(balance(alice, startBalance - drops(4 * baseFee)));
            env.require(
                balance(bob, startBalance + XRP(100) - drops(3 * baseFee)));
            env.require(
                balance(carol, startBalance - XRP(100) - drops(5 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 4);

            // now alice can pay bob
            env(pay(alice, bob, XRP(100)));
            env(pay(alice, bob, USD(100)));
            env.close();
            env.require(
                balance(alice, startBalance - XRP(100) - drops(6 * baseFee)));
            env.require(
                balance(bob, startBalance + XRP(200) - drops(3 * baseFee)));
            env.require(
                balance(carol, startBalance - XRP(100) - drops(5 * baseFee)));
            env.require(balance(alice, USD(900)));
            env.require(balance(bob, USD(1200)));
            env.require(balance(carol, USD(900)));

            // bob give permission to alice to auth/unauth on behalf of himself
            env(account_permission::accountPermissionSet(
                bob, alice, {"DepositPreauth"}));
            env.close();
            env.require(
                balance(bob, startBalance + XRP(200) - drops(4 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 5);

            // now alice unauthorize carol to pay bob on behalf of bob
            env(deposit::unauth(alice, carol, bob));
            env.close();
            env.require(
                balance(alice, startBalance - XRP(100) - drops(7 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 4);

            // carol can not pay bob
            env(pay(carol, bob, XRP(100)), ter(tecNO_PERMISSION));
            env(pay(carol, bob, USD(100)), ter(tecNO_PERMISSION));
            env.close();
            env.require(
                balance(carol, startBalance - XRP(100) - drops(7 * baseFee)));

            // alice can still pay bob
            env(pay(alice, bob, XRP(100)));
            env(pay(alice, bob, USD(100)));
            env.close();
            env.require(
                balance(alice, startBalance - XRP(200) - drops(9 * baseFee)));
            env.require(
                balance(bob, startBalance + XRP(300) - drops(4 * baseFee)));
            env.require(balance(alice, USD(800)));
            env.require(balance(bob, USD(1300)));

            // alice unauth herself to pay bob on behalf of bob
            env(deposit::unauth(alice, alice, bob));
            env.close();
            env.require(
                balance(alice, startBalance - XRP(200) - drops(10 * baseFee)));
            env.require(
                balance(bob, startBalance + XRP(300) - drops(4 * baseFee)));
            env.require(
                balance(carol, startBalance - XRP(100) - drops(7 * baseFee)));
            BEAST_EXPECT(ownerCount(env, bob) == 3);

            // now alice can not pay bob
            env(pay(alice, bob, XRP(100)), ter(tecNO_PERMISSION));
            env(pay(alice, bob, USD(100)), ter(tecNO_PERMISSION));
            // carol still can not pay bob
            env(pay(carol, bob, XRP(100)), ter(tecNO_PERMISSION));
            env(pay(carol, bob, USD(100)), ter(tecNO_PERMISSION));
            env.require(
                balance(alice, startBalance - XRP(200) - drops(12 * baseFee)));
            env.require(
                balance(carol, startBalance - XRP(100) - drops(9 * baseFee)));

            env(fclear(bob, asfDepositAuth));
            env.close();

            // now alice and carol can pay bob
            env(pay(alice, bob, XRP(100)));
            env(pay(alice, bob, USD(100)));
            env(pay(carol, bob, XRP(100)));
            env(pay(carol, bob, USD(100)));
            env.close();
        }

        {
            const char credType[] = "abcde";
            const char uri[] = "uri";
            Env env(*this, features);

            Account alice{"alice"};
            Account bob{"bob"};
            Account issuer{"issuer"};
            Account subject{"subject"};
            env.fund(XRP(5000), alice, bob, issuer, subject);
            env.close();

            env(fset(bob, asfDepositAuth));
            env.close();

            env(account_permission::accountPermissionSet(
                issuer, alice, {"CredentialCreate"}));
            env.close();
            BEAST_EXPECT(ownerCount(env, issuer) == 1);
            BEAST_EXPECT(ownerCount(env, alice) == 0);

            // alice creates credential on behalf of issuer successfully
            env(credentials::create(subject, alice, credType),
                credentials::uri(uri),
                onBehalfOf(issuer));
            env.close();
            BEAST_EXPECT(ownerCount(env, issuer) == 2);

            // Get the index of the credentials
            auto const jv =
                credentials::ledgerEntry(env, subject, issuer, credType);
            std::string const credIdx = jv[jss::result][jss::index].asString();

            env(account_permission::accountPermissionSet(
                bob, alice, {"DepositPreauth"}));
            env.close();

            // alice send DepositPreauth on behalf of bob.
            // bob will accept payements from accounts with credentials signed
            // by issuer
            env(deposit::authCredentials(alice, {{issuer, credType}}),
                onBehalfOf(bob));
            env.close();

            auto const jDP = deposit::ledgerEntryDepositPreauth(
                env, bob, {{issuer, credType}});
            BEAST_EXPECT(
                jDP.isObject() && jDP.isMember(jss::result) &&
                !jDP[jss::result].isMember(jss::error) &&
                jDP[jss::result].isMember(jss::node) &&
                jDP[jss::result][jss::node].isMember("LedgerEntryType") &&
                jDP[jss::result][jss::node]["LedgerEntryType"] ==
                    jss::DepositPreauth);

            // credentials are not accepted yet
            env(pay(subject, bob, XRP(100)),
                credentials::ids({credIdx}),
                ter(tecBAD_CREDENTIALS));
            env.close();

            // alice accept credentials on behalf of subject
            env(account_permission::accountPermissionSet(
                subject, alice, {"CredentialAccept"}));
            env.close();

            env(credentials::accept(alice, issuer, credType),
                onBehalfOf(subject));
            env.close();

            // now subject can pay bob
            env(pay(subject, bob, XRP(100)), credentials::ids({credIdx}));
            env.close();

            // subject can pay alice because alice did not enable depositAuth
            env(pay(subject, alice, XRP(250)), credentials::ids({credIdx}));
            env.close();

            Account carol{"carol"};
            env.fund(XRP(5000), carol);
            env.close();

            env(fset(carol, asfDepositAuth));
            env.close();

            // carol did not setup DepositPreauth
            env(pay(subject, carol, XRP(100)),
                credentials::ids({credIdx}),
                ter(tecNO_PERMISSION));

            // bob setup depositPreauth on behalf of carol
            env(account_permission::accountPermissionSet(
                carol, bob, {"DepositPreauth"}));
            env.close();

            env(deposit::authCredentials(bob, {{issuer, credType}}),
                onBehalfOf(carol));
            env.close();

            const char credType2[] = "fghij";
            env(credentials::create(subject, issuer, credType2));
            env.close();
            env(credentials::accept(subject, issuer, credType2));
            env.close();
            auto const jv2 =
                credentials::ledgerEntry(env, subject, issuer, credType2);
            std::string const credIdx2 =
                jv2[jss::result][jss::index].asString();

            // unable to pay with invalid set of credentials
            env(pay(subject, carol, XRP(100)),
                credentials::ids({credIdx, credIdx2}),
                ter(tecNO_PERMISSION));

            env(pay(subject, carol, XRP(100)), credentials::ids({credIdx}));
            env.close();
        }
    }

    void
    testDID(FeatureBitset features)
    {
        testcase("test DIDSet, DIDDelete");
        using namespace jtx;

        Env env(*this, features);
        XRPAmount const baseFee{env.current()->fees().base};
        STAmount const startBalance{XRP(1000000).value()};

        Account alice{"alice"};
        Account bob{"bob"};
        Account carol{"carol"};
        env.fund(startBalance, alice, bob, carol);
        env.close();

        // alice give permission to bob and carol for DIDSet and DIDDelete
        env(account_permission::accountPermissionSet(
            alice, bob, {"DIDSet", "DIDDelete"}));
        env(account_permission::accountPermissionSet(
            alice, carol, {"DIDSet", "DIDDelete"}));
        env.close();
        env.require(balance(alice, startBalance - drops(2 * baseFee)));
        BEAST_EXPECT(ownerCount(env, alice) == 2);

        // bob set uri and doc on behalf of alice
        std::string const uri = "uri";
        std::string const doc = "doc";
        std::string const data = "data";
        env(did::set(bob),
            did::uri(uri),
            did::document(doc),
            onBehalfOf(alice));
        env.close();
        env.require(balance(alice, startBalance - drops(2 * baseFee)));
        env.require(balance(bob, startBalance - drops(baseFee)));
        env.require(balance(carol, startBalance));
        BEAST_EXPECT(ownerCount(env, alice) == 3);
        BEAST_EXPECT(ownerCount(env, bob) == 0);
        BEAST_EXPECT(ownerCount(env, carol) == 0);
        auto sleDID = env.le(keylet::did(alice.id()));
        BEAST_EXPECT(sleDID);
        BEAST_EXPECT(did::checkVL((*sleDID)[sfURI], uri));
        BEAST_EXPECT(did::checkVL((*sleDID)[sfDIDDocument], doc));
        BEAST_EXPECT(!sleDID->isFieldPresent(sfData));

        // carol set data, update document and remove uri on behalf of alice
        std::string const doc2 = "doc2";
        env(did::set(carol),
            did::uri(""),
            did::document(doc2),
            did::data(data),
            onBehalfOf(alice));
        env.close();
        env.require(balance(alice, startBalance - drops(2 * baseFee)));
        env.require(balance(bob, startBalance - drops(baseFee)));
        env.require(balance(carol, startBalance - drops(baseFee)));
        BEAST_EXPECT(ownerCount(env, alice) == 3);
        BEAST_EXPECT(ownerCount(env, bob) == 0);
        BEAST_EXPECT(ownerCount(env, carol) == 0);
        sleDID = env.le(keylet::did(alice.id()));
        BEAST_EXPECT(sleDID);
        BEAST_EXPECT(!sleDID->isFieldPresent(sfURI));
        BEAST_EXPECT(did::checkVL((*sleDID)[sfDIDDocument], doc2));
        BEAST_EXPECT(did::checkVL((*sleDID)[sfData], data));

        // bob delete DID on behalf of alice
        env(did::del(bob, alice));
        env.close();
        env.require(balance(alice, startBalance - drops(2 * baseFee)));
        env.require(balance(bob, startBalance - drops(2 * baseFee)));
        env.require(balance(carol, startBalance - drops(baseFee)));
        BEAST_EXPECT(ownerCount(env, alice) == 2);
        BEAST_EXPECT(ownerCount(env, bob) == 0);
        BEAST_EXPECT(ownerCount(env, carol) == 0);
        sleDID = env.le(keylet::did(alice.id()));
        BEAST_EXPECT(!sleDID);
    }

    void
    testEscrow(FeatureBitset features)
    {
        std::array<std::uint8_t, 4> const fb1 = {{0xA0, 0x02, 0x80, 0x00}};

        std::array<std::uint8_t, 39> const cb1 = {
            {0xA0, 0x25, 0x80, 0x20, 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC,
             0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
             0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95,
             0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55, 0x81, 0x01, 0x00}};

        testcase("test EscrowCreate, EscrowCancel, EscrowFinish");
        using namespace jtx;

        Env env(*this, features);
        XRPAmount const baseFee{env.current()->fees().base};

        Account alice{"alice"};
        Account bob{"bob"};
        Account carol{"carol"};
        env.fund(XRP(1000000), alice, bob, carol);
        env.close();

        STAmount aliceXrpBalance, bobXrpBalance, carolXrpBalance;
        auto UpdateXrpBalances = [&]() {
            aliceXrpBalance = env.balance(alice, XRP);
            bobXrpBalance = env.balance(bob, XRP);
            carolXrpBalance = env.balance(carol, XRP);
        };

        env(account_permission::accountPermissionSet(
            alice, bob, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
        env(account_permission::accountPermissionSet(
            alice, carol, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
        env(account_permission::accountPermissionSet(
            bob, alice, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
        env(account_permission::accountPermissionSet(
            bob, carol, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
        env(account_permission::accountPermissionSet(
            carol, alice, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
        env(account_permission::accountPermissionSet(
            carol, bob, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
        env.close();

        BEAST_EXPECT(ownerCount(env, alice) == 2);
        BEAST_EXPECT(ownerCount(env, bob) == 2);
        BEAST_EXPECT(ownerCount(env, carol) == 2);

        // test send basic EscrowCreate, EscrowCancel, EscrowFinish transactions
        // on behalf of others
        {
            UpdateXrpBalances();
            auto const ts = env.now() + std::chrono::seconds(90);
            // bob creates escrow on behalf of alice, destination is carol
            // (alice->carol)
            auto const seq1 = env.seq(alice);
            env(escrow(bob, carol, XRP(1000)),
                onBehalfOf(alice),
                finish_time(ts));
            env.close();
            env.require(balance(alice, aliceXrpBalance - XRP(1000)));
            env.require(balance(bob, bobXrpBalance - drops(baseFee)));
            BEAST_EXPECT(ownerCount(env, alice) == 3);
            BEAST_EXPECT(ownerCount(env, bob) == 2);
            BEAST_EXPECT(ownerCount(env, carol) == 2);

            UpdateXrpBalances();
            // carol creates escrow on behalf of alice, destination is bob
            // (alice->bob)
            auto const seq2 = env.seq(alice);
            env(escrow(carol, bob, XRP(2000)),
                onBehalfOf(alice),
                cancel_time(ts),
                condition(cb1));
            env.close();
            env.require(balance(alice, aliceXrpBalance - XRP(2000)));
            env.require(balance(bob, bobXrpBalance));
            env.require(balance(carol, carolXrpBalance - drops(baseFee)));
            BEAST_EXPECT(ownerCount(env, alice) == 4);
            BEAST_EXPECT(ownerCount(env, bob) == 2);
            BEAST_EXPECT(ownerCount(env, carol) == 2);

            UpdateXrpBalances();
            // bob creates escrow on behalf of alice again, destination is carol
            // (alice->carol)
            auto const seq3 = env.seq(alice);
            env(escrow(bob, carol, XRP(3000)),
                onBehalfOf(alice),
                finish_time(ts));
            env.close();
            env.require(balance(alice, aliceXrpBalance - XRP(3000)));
            env.require(balance(bob, bobXrpBalance - drops(baseFee)));
            env.require(balance(carol, carolXrpBalance));
            BEAST_EXPECT(ownerCount(env, alice) == 5);
            BEAST_EXPECT(ownerCount(env, bob) == 2);
            BEAST_EXPECT(ownerCount(env, carol) == 2);

            // finish and cancel won't complete prematurely.
            for (; env.now() <= ts; env.close())
            {
                // alice finish seq1 on behalf of bob, the escrow's owner is
                // alice
                env(finish(alice, alice, seq1),
                    onBehalfOf(carol),
                    fee(1500),
                    ter(tecNO_PERMISSION));

                // alice cancel seq2 on behalf of bob, the escrow's owner is
                // alice
                env(cancel(alice, alice, seq1),
                    onBehalfOf(bob),
                    fee(1500),
                    ter(tecNO_PERMISSION));

                // bob finish seq3 on behalf of carol, the escrow's owner is
                // alice
                env(finish(bob, alice, seq3),
                    onBehalfOf(carol),
                    fee(1500),
                    ter(tecNO_PERMISSION));
            }

            UpdateXrpBalances();
            // alice finish escrow seq1 on behalf of carol.
            // alice is the owner.
            env(finish(alice, alice, seq1),
                onBehalfOf(carol),
                fee(1500),
                ter(tesSUCCESS));
            env.close();
            env.require(balance(alice, aliceXrpBalance - drops(1500)));
            env.require(balance(bob, bobXrpBalance));
            env.require(balance(carol, carolXrpBalance + XRP(1000)));
            BEAST_EXPECT(ownerCount(env, alice) == 4);

            UpdateXrpBalances();
            // finish won't work for escrow seq2
            env(finish(alice, alice, seq2),
                condition(cb1),
                fulfillment(fb1),
                onBehalfOf(bob),
                fee(1500),
                ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(alice, aliceXrpBalance - drops(1500)));
            env.require(balance(bob, bobXrpBalance));
            env.require(balance(carol, carolXrpBalance));
            BEAST_EXPECT(ownerCount(env, alice) == 4);

            UpdateXrpBalances();
            // alice cancel escrow seq2 on behalf of bob
            env(cancel(alice, alice, seq2), onBehalfOf(bob), fee(1500));
            env.close();
            env.require(
                balance(alice, aliceXrpBalance + XRP(2000) - drops(1500)));
            env.require(balance(bob, bobXrpBalance));
            env.require(balance(carol, carolXrpBalance));
            BEAST_EXPECT(ownerCount(env, alice) == 3);

            UpdateXrpBalances();
            // bob finish escrow seq3 on behalf of carol
            env(finish(bob, alice, seq3),
                onBehalfOf(carol),
                fee(1500),
                ter(tesSUCCESS));
            env.close();
            env.require(balance(alice, aliceXrpBalance));
            env.require(balance(bob, bobXrpBalance - drops(1500)));
            env.require(balance(carol, carolXrpBalance + XRP(3000)));
            BEAST_EXPECT(ownerCount(env, alice) == 2);
        }

        // test escrow with FinishAfter earlier than CancelAfter
        {
            auto const fts = env.now() + std::chrono::seconds(117);
            auto const cts = env.now() + std::chrono::seconds(192);

            UpdateXrpBalances();
            // alice creates escrow on behalf of carol, destination is bob
            // (carol->bob)
            auto const seq = env.seq(carol);
            env(escrow(alice, bob, XRP(1000)),
                onBehalfOf(carol),
                finish_time(fts),
                cancel_time(cts),
                stag(1),
                dtag(2));
            env.close();

            auto const sle = env.le(keylet::escrow(carol.id(), seq));
            BEAST_EXPECT(sle);
            BEAST_EXPECT((*sle)[sfSourceTag] == 1);
            BEAST_EXPECT((*sle)[sfDestinationTag] == 2);

            env.require(balance(alice, aliceXrpBalance - drops(baseFee)));
            env.require(balance(carol, carolXrpBalance - XRP(1000)));

            // finish and cancel won't complete prematurely.
            for (; env.now() <= fts; env.close())
            {
                // bob finish escrow seq on behalf of carol
                env(finish(bob, carol, seq),
                    onBehalfOf(carol),
                    fee(1500),
                    ter(tecNO_PERMISSION));

                // bob cancel escrow seq on behalf of carol
                env(cancel(bob, carol, seq),
                    onBehalfOf(carol),
                    fee(1500),
                    ter(tecNO_PERMISSION));
            }

            UpdateXrpBalances();
            // still can not cancel before CancelAfter time
            env(cancel(alice, carol, seq),
                onBehalfOf(bob),
                fee(1500),
                ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(alice, aliceXrpBalance - drops(1500)));
            env.require(balance(bob, bobXrpBalance));
            env.require(balance(carol, carolXrpBalance));

            // can finish after FinishAfter time
            env(finish(alice, carol, seq), onBehalfOf(bob), fee(1500));
            env.close();
            env.require(balance(alice, aliceXrpBalance - drops(3000)));
            env.require(balance(bob, bobXrpBalance + XRP(1000)));
            env.require(balance(carol, carolXrpBalance));
        }

        {
            Account gw("gw");
            Account david{"david"};
            Account emma{"emma"};
            Account frank{"frank"};
            env.fund(XRP(5000), gw, david, emma, frank);
            env(fset(david, asfDepositAuth));
            env.close();
            env(deposit::auth(david, emma));
            env.close();

            auto const seq = env.seq(gw);
            auto const fts = env.now() + std::chrono::seconds(5);
            env(escrow(gw, david, XRP(1000)), finish_time(fts));
            env.require(balance(gw, XRP(4000) - drops(baseFee)));
            env.close();

            env(account_permission::accountPermissionSet(
                emma, frank, {"EscrowCreate", "EscrowCancel", "EscrowFinish"}));
            env.close();

            while (env.now() <= fts)
                env.close();

            // gw has no permission
            env(finish(gw, gw, seq), ter(tecNO_PERMISSION));

            auto davidXrpBalance = env.balance(david, XRP);
            // but frank can finish onbehalf of emma because emma is
            // preauthorized
            env(finish(frank, gw, seq), onBehalfOf(emma));
            env.close();
            env.require(balance(david, davidXrpBalance + XRP(1000)));
        }
    }

    void
    testMPToken(FeatureBitset features)
    {
        testcase("test MPT transactions");
        using namespace jtx;

        {
            Env env(*this, features);
            XRPAmount const baseFee{env.current()->fees().base};
            STAmount const startBalance{XRP(1000000).value()};

            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(startBalance, alice, bob, carol);
            env.close();

            // sender is alice, bob is issuer
            MPTTester mpt(env, alice, bob);
            env.close();

            // Account alice{"alice"};
            // Account bob{"bob"};
            // Account carol{"carol"};
            // env.fund(startBalance, carol);
            // env.close();

            // sender is alice, bob is issuer
            // MPTTester mpt(env, bob, {.holders = {alice}});
            // env.close();

            // alice can send MPTokenIssuanceCreate on behalf of bob
            env(account_permission::accountPermissionSet(
                bob,
                alice,
                {"MPTokenIssuanceCreate", "MPTokenIssuanceDestroy"}));

            // env(account_permission::accountPermissionSet(
            //     alice, carol, {"MPTokenAuthorize"}));

            // use sender's account to generate id
            auto const id = makeMptID(env.seq(alice), alice);
            // auto const id = makeMptID(env.seq(bob), bob);
            //  bob owns AccountPermission and MPTokenIssuance
            // mpt.create({.ownerCount = 1});
            mpt.create({.onBehalfOf = bob});
            // mpt.create(
            //     {.maxAmt = maxMPTokenAmount,  // 9'223'372'036'854'775'807
            //      .assetScale = 1,
            //      .transferFee = 10,
            //      .metadata = "123",
            //      .ownerCount = 2,
            //      //.onBehalfOf = bob,
            //      .flags = tfMPTCanLock | tfMPTRequireAuth | tfMPTCanEscrow |
            //          tfMPTCanTrade | tfMPTCanTransfer | tfMPTCanClawback});

            // Get the hash for the most recent transaction.
            std::string const txHash{
                env.tx()->getJson(JsonOptions::none)[jss::hash].asString()};
            std::cout << env.rpc("tx", txHash) << std::endl;

            // Json::Value const result = env.rpc("tx", txHash)[jss::result];
            // BEAST_EXPECT(
            //     result[sfMaximumAmount.getJsonName()] ==
            //     "9223372036854775807");

            // alice hold the mptoken object (carol sent on behalf of alice)
            // mpt.authorize({.account = alice, .holderCount = 1, .onBehalfOf =
            // alice});
            mpt.authorize({.account = alice, .holderCount = 1});

            // alice can not create mptoken again
            // mpt.authorize({.account = alice, .err = tecDUPLICATE});
            env.close();

            // bob pays alice 100 tokens
            mpt.pay(bob, alice, 100);
            // // alice destroy MPT on behalf of bob, bob will only own
            // AccountPermission mpt.destroy({.id = id, .onBehalfOf = bob,
            // .ownerCount = 1});
        }
    }

    void
    testOracle(FeatureBitset features)
    {
        testcase("test oracle");
        using namespace jtx;

        Env env(*this, features);
        Account alice{"alice"};
        Account bob{"bob"};
        env.fund(XRP(1'000), alice, bob);

        env(account_permission::accountPermissionSet(
            bob, alice, {"OracleSet", "OracleDelete"}));
        env.close();

        // alice create oracle on behalf of bob
        oracle::Oracle oracle(
            env,
            {.sender = alice,
             .onBehalfOf = bob,
             .series = {{"XRP", "USD", 740, 1}}});
        BEAST_EXPECT(oracle.exists());
        BEAST_EXPECT(ownerCount(env, alice) == 0);
        BEAST_EXPECT(ownerCount(env, bob) == 2);
        // bob delete oracle himself
        oracle.remove({});
        BEAST_EXPECT(!oracle.exists());
        BEAST_EXPECT(ownerCount(env, bob) == 1);

        // alice create oracle2 on behalf of bob
        oracle::Oracle oracle2(env, {.sender = alice, .onBehalfOf = bob});
        BEAST_EXPECT(oracle2.exists());
        BEAST_EXPECT(ownerCount(env, alice) == 0);
        BEAST_EXPECT(ownerCount(env, bob) == 2);

        // alice updates oracle2 on behalf of bob
        oracle2.set(oracle::UpdateArg{
            .sender = alice,
            .onBehalfOf = bob,
            .series = {{"XRP", "USD", 740, 2}}});
        BEAST_EXPECT(oracle2.expectPrice({{"XRP", "USD", 740, 2}}));
        BEAST_EXPECT(ownerCount(env, alice) == 0);
        BEAST_EXPECT(ownerCount(env, bob) == 2);

        oracle2.set(oracle::UpdateArg{
            .sender = alice,
            .onBehalfOf = bob,
            .series = {{"XRP", "EUR", 700, 2}}});
        BEAST_EXPECT(oracle2.expectPrice(
            {{"XRP", "USD", 0, 0}, {"XRP", "EUR", 700, 2}}));
        BEAST_EXPECT(ownerCount(env, bob) == 2);

        // bob updates oracle2 himself
        oracle2.set(oracle::UpdateArg{
            .series = {{"XRP", "USD", 741, 2}, {"XRP", "EUR", 710, 2}}});
        BEAST_EXPECT(oracle2.expectPrice(
            {{"XRP", "USD", 741, 2}, {"XRP", "EUR", 710, 2}}));
        BEAST_EXPECT(ownerCount(env, bob) == 2);

        // alice updates oracle2 on behalf of bob
        oracle2.set(oracle::UpdateArg{
            .sender = alice,
            .onBehalfOf = bob,
            .series = {
                {"BTC", "USD", 741, 2},
                {"ETH", "EUR", 710, 2},
                {"YAN", "EUR", 710, 2},
                {"CAN", "EUR", 710, 2},
            }});
        BEAST_EXPECT(ownerCount(env, bob) == 3);

        oracle2.set(oracle::UpdateArg{
            .series = {{"BTC", "USD", std::nullopt, std::nullopt}}});

        oracle2.set(oracle::UpdateArg{
            .sender = alice,
            .onBehalfOf = bob,
            .series = {
                {"XRP", "USD", 742, 2},
                {"XRP", "EUR", 711, 2},
                {"ETH", "EUR", std::nullopt, std::nullopt},
                {"YAN", "EUR", std::nullopt, std::nullopt},
                {"CAN", "EUR", std::nullopt, std::nullopt}}});
        BEAST_EXPECT(oracle2.expectPrice(
            {{"XRP", "USD", 742, 2}, {"XRP", "EUR", 711, 2}}));

        BEAST_EXPECT(ownerCount(env, bob) == 2);

        auto const index = env.closed()->seq();
        auto const hash = env.closed()->info().hash;
        for (int i = 0; i < 256; ++i)
            env.close();
        auto const acctDelFee{drops(env.current()->fees().increment)};

        // deleting account bob deletes oracle2
        env(acctdelete(bob, alice), fee(acctDelFee));
        env.close();
        BEAST_EXPECT(!oracle2.exists());

        // can still get the oracles via the ledger index or hash
        auto verifyLedgerData = [&](auto const& field, auto const& value) {
            Json::Value jvParams;
            jvParams[field] = value;
            jvParams[jss::binary] = false;
            jvParams[jss::type] = jss::oracle;
            Json::Value jrr = env.rpc(
                "json",
                "ledger_data",
                boost::lexical_cast<std::string>(jvParams));
            BEAST_EXPECT(jrr[jss::result][jss::state].size() == 1);
        };
        verifyLedgerData(jss::ledger_index, index);
        verifyLedgerData(jss::ledger_hash, to_string(hash));
    }

    void
    testTrustSet(FeatureBitset features)
    {
        testcase("test TrustSet");
        using namespace jtx;

        // test create trustline
        {
            Env env(*this, features);
            Account gw{"gw"};
            Account alice{"alice"};
            Account bob{"bob"};
            env.fund(XRP(1'000), gw, alice, bob);

            env(account_permission::accountPermissionSet(
                bob, alice, {"TrustSet"}));

            // alice send trustset on behalf of bob
            env(trust(alice, gw["USD"](50), 0), onBehalfOf(bob));
            env.close();

            env.require(lines(gw, 1));
            env.require(lines(bob, 1));

            Json::Value jv;
            jv["account"] = bob.human();
            auto bobLines = env.rpc("json", "account_lines", to_string(jv));

            jv["account"] = gw.human();
            auto gwLines = env.rpc("json", "account_lines", to_string(jv));

            BEAST_EXPECT(bobLines[jss::result][jss::lines].size() == 1);
            BEAST_EXPECT(gwLines[jss::result][jss::lines].size() == 1);

            // pay exceeding trustline limit
            env(pay(gw, bob, gw["USD"](200)), ter(tecPATH_PARTIAL));
            env.close();

            // smaller payments should succeed
            env(pay(gw, bob, gw["USD"](20)), ter(tesSUCCESS));
            env.close();

            env.require(balance(bob, gw["USD"](20)));
            env.require(balance(gw, bob["USD"](-20)));
        }

        // test requireAuth
        {
            Env env(*this, features);
            Account gw{"gw"};
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(XRP(1'000), gw, alice, bob, carol);

            env(fset(gw, asfRequireAuth));
            env.close();
            env.require(flags(gw, asfRequireAuth));

            env(account_permission::accountPermissionSet(
                bob, alice, {"TrustSet"}));
            env(account_permission::accountPermissionSet(
                gw, alice, {"TrustSet"}));
            env.close();

            // alice send trustset on behalf of gw, but source can not be the
            // same as destination
            env(trust(alice, gw["USD"](50), 0),
                onBehalfOf(gw),
                ter(temDST_IS_SRC));
            env.close();

            // alice send trustset on behalf of bob
            env(trust(alice, gw["USD"](50), 0), onBehalfOf(bob));
            env.close();

            env(pay(gw, bob, gw["USD"](10)), ter(tecPATH_DRY));
            env.close();

            // alice authorizes bob to hold gw["USD"] on behalf of gw
            env(trust(alice, gw["USD"](0), bob, tfSetfAuth), onBehalfOf(gw));
            env.close();

            env.require(lines(gw, 1));
            env.require(lines(bob, 1));

            Json::Value jv;
            jv["account"] = bob.human();
            auto bobLines = env.rpc("json", "account_lines", to_string(jv));

            jv["account"] = gw.human();
            auto gwLines = env.rpc("json", "account_lines", to_string(jv));

            BEAST_EXPECT(bobLines[jss::result][jss::lines].size() == 1);
            BEAST_EXPECT(gwLines[jss::result][jss::lines].size() == 1);

            // alice resets trust line limit to 0 on behalf of bob
            // this will delete the trust line
            env(trust(alice, gw["USD"](0), 0), onBehalfOf(bob));
            env.close();

            env.require(lines(gw, 0));
            env.require(lines(bob, 0));
        }

        // create trustline to each other
        {
            Env env(*this, features);
            Account gw{"gw"};
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(XRP(1'000), gw, alice, bob, carol);
            env.close();

            env(account_permission::accountPermissionSet(
                alice, bob, {"TrustSet"}));
            env(account_permission::accountPermissionSet(
                bob, alice, {"TrustSet"}));
            env.close();
            BEAST_EXPECT(ownerCount(env, alice) == 1);
            BEAST_EXPECT(ownerCount(env, bob) == 1);

            // alice creates trustline to alice on behalf of bob
            env(trust(alice, alice["USD"](100)), onBehalfOf(bob));
            env.close();
            BEAST_EXPECT(ownerCount(env, alice) == 1);
            BEAST_EXPECT(ownerCount(env, bob) == 2);

            env.require(lines(alice, 1));
            env.require(lines(bob, 1));

            env(pay(alice, bob, alice["USD"](20)), ter(tesSUCCESS));
            env.close();
            env.require(balance(bob, alice["USD"](20)));
            env.require(balance(alice, bob["USD"](-20)));

            env(pay(bob, alice, bob["USD"](10)), ter(tesSUCCESS));
            env.close();
            env.require(balance(bob, alice["USD"](10)));
            env.require(balance(alice, bob["USD"](-10)));

            env(pay(bob, alice, bob["USD"](11)), ter(tecPATH_PARTIAL));
            env.close();
            env.require(balance(bob, alice["USD"](10)));
            env.require(balance(alice, bob["USD"](-10)));

            env(pay(bob, alice, bob["USD"](10)), ter(tesSUCCESS));
            env.close();
            env.require(balance(bob, alice["USD"](0)));
            env.require(balance(alice, bob["USD"](0)));

            env(trust(bob, bob["USD"](100)), onBehalfOf(alice));
            env.close();
            env(pay(bob, alice, bob["USD"](5)), ter(tesSUCCESS));
            env.close();

            env.require(lines(alice, 1));
            env.require(lines(bob, 1));

            env.require(balance(bob, alice["USD"](-5)));
            env.require(balance(alice, bob["USD"](5)));
        }

        // create trustline when asfDisallowIncomingTrustline is set
        // create trustline with tfSetNoRipple
        {
            Env env(*this, features);
            Account gw{"gw"};
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(XRP(1'000), gw, alice, bob, carol);
            env.close();

            env(fset(gw, asfDisallowIncomingTrustline));
            env.close();

            env(account_permission::accountPermissionSet(
                bob, alice, {"TrustSet"}));
            env(account_permission::accountPermissionSet(
                gw, alice, {"TrustSet"}));
            env.close();

            // can not create trustline when asfDisallowIncomingTrustline is set
            auto const USD = gw["USD"];
            env(trust(alice, USD(1000)),
                onBehalfOf(bob),
                ter(tecNO_PERMISSION));
            env.close();

            env(fclear(gw, asfDisallowIncomingTrustline));
            env.close();

            // alice can create trustline on behalf of bob when
            // asfDisallowIncomingTrustline is cleared
            env(trust(alice, USD(1000)), onBehalfOf(bob));
            env.close();

            env(pay(gw, bob, USD(200)));
            env.close();
            env.require(balance(gw, bob["USD"](-200)));
            env.require(balance(bob, gw["USD"](200)));

            // alice create trustline on behalf of gw to carol with
            // tfSetNoRipple flag
            env(trust(alice, USD(2000), carol, tfSetNoRipple), onBehalfOf(gw));
            env.close();

            Json::Value carolJson;
            carolJson[jss::account] = carol.human();
            Json::Value response =
                env.rpc("json", "account_lines", to_string(carolJson));
            auto const& line = response[jss::result][jss::lines][0u];
            BEAST_EXPECT(line[jss::no_ripple_peer].asBool() == true);
        }
    }

    void
    testXChain(FeatureBitset features)
    {
        testcase("test XChain transactions");
        using namespace jtx;

        // create two chains
        Env env(*this, features);
        Env envX(*this, jtx::envconfig(jtx::port_increment, 3), features);
        XRPAmount const baseFee{env.current()->fees().base};

        // fund initial accounts
        Account door = Account("door");
        Account alice = Account("alice");
        Account bob = Account("bob");
        env.fund(XRP(100000), door, alice, bob);
        env.close();
        Account attesterX = Account("attesterX");
        Account signerX = Account("signerX");
        Account rewardX = Account("rewardX");
        Account aliceX = Account("aliceX");
        Account bobX = Account("bobX");
        Account carolX = Account{"carolX"};
        envX.fund(XRP(100000), attesterX, signerX, rewardX, bobX, carolX);
        envX.close();
        std::vector<jtx::signer> signerXs = {jtx::signer(signerX)};

        auto doorBalance = env.balance(door, XRP);
        auto aliceBalance = env.balance(alice, XRP);
        auto bobBalance = env.balance(bob, XRP);
        // door on the side chain has to be master account for XRP
        auto doorXBalance = envX.balance(Account::master, XRP);
        auto attesterXBalance = envX.balance(attesterX, XRP);
        auto signerXBalance = envX.balance(signerX, XRP);
        auto rewardXBalance = envX.balance(rewardX, XRP);
        auto aliceXBalance = envX.balance(aliceX, XRP);
        auto bobXBalance = envX.balance(bobX, XRP);
        auto carolXBalance = envX.balance(carolX, XRP);

        // XChainCreateBridge
        Json::Value jvBridge =
            bridge(door, xrpIssue(), Account::master, xrpIssue());
        {
            env(bridge_create(bob, jvBridge, XRP(1), XRP(100)),
                onBehalfOf(door),
                ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            bobBalance = env.balance(bob, XRP);

            env(account_permission::accountPermissionSet(
                door, bob, {"XChainCreateBridge"}));
            env.close();
            env.require(balance(door, doorBalance - drops(baseFee)));
            doorBalance = env.balance(door, XRP);

            env(bridge_create(bob, jvBridge, XRP(1), XRP(100)),
                onBehalfOf(door));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            bobBalance = env.balance(bob, XRP);
        }
        {
            envX(
                bridge_create(bobX, jvBridge, XRP(1), XRP(100)),
                onBehalfOf(Account::master),
                ter(tecNO_PERMISSION));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            envX(account_permission::accountPermissionSet(
                Account::master, bobX, {"XChainCreateBridge"}));
            envX.close();
            envX.require(
                balance(Account::master, doorXBalance - drops(baseFee)));
            doorXBalance = envX.balance(Account::master, XRP);

            envX(
                bridge_create(bobX, jvBridge, XRP(1), XRP(100)),
                onBehalfOf(Account::master));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            // set up signer on envX
            envX(jtx::signers(Account::master, 1, signerXs));
            envX.close();
            envX.require(
                balance(Account::master, doorXBalance - drops(baseFee)));
            doorXBalance = envX.balance(Account::master, XRP);
        }

        // XChainModifyBridge
        {
            env(bridge_modify(bob, jvBridge, XRP(2), XRP(200)),
                onBehalfOf(door),
                ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            bobBalance = env.balance(bob, XRP);

            env(account_permission::accountPermissionSet(
                door, bob, {"XChainModifyBridge"}));
            env.close();
            env.require(balance(door, doorBalance - drops(baseFee)));
            doorBalance = env.balance(door, XRP);

            env(bridge_modify(bob, jvBridge, XRP(2), XRP(200)),
                onBehalfOf(door));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            bobBalance = env.balance(bob, XRP);
        }
        {
            envX(
                bridge_modify(bobX, jvBridge, XRP(2), XRP(200)),
                onBehalfOf(Account::master),
                ter(tecNO_PERMISSION));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            envX(account_permission::accountPermissionSet(
                Account::master, bobX, {"XChainModifyBridge"}));
            envX.close();
            envX.require(
                balance(Account::master, doorXBalance - drops(baseFee)));
            doorXBalance = envX.balance(Account::master, XRP);

            envX(
                bridge_modify(bobX, jvBridge, XRP(2), XRP(200)),
                onBehalfOf(Account::master));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);
        }

        // XChainAccountCreateCommit
        {
            env(sidechain_xchain_account_create(
                    bob, jvBridge, aliceX, XRP(10000), XRP(2)),
                onBehalfOf(alice),
                ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            bobBalance = env.balance(bob, XRP);

            env(account_permission::accountPermissionSet(
                alice, bob, {"XChainAccountCreateCommit"}));
            env.close();
            env.require(balance(alice, aliceBalance - drops(baseFee)));
            aliceBalance = env.balance(alice, XRP);

            env(sidechain_xchain_account_create(
                    bob, jvBridge, aliceX, XRP(10000), XRP(2)),
                onBehalfOf(alice));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            env.require(balance(alice, aliceBalance - XRP(10000) - XRP(2)));
            env.require(balance(door, doorBalance + XRP(10000) + XRP(2)));
            bobBalance = env.balance(bob, XRP);
            aliceBalance = env.balance(alice, XRP);
            doorBalance = env.balance(door, XRP);
        }

        // XChainAddAccountCreateAttestation
        {
            envX(
                create_account_attestation(
                    bobX,
                    jvBridge,
                    alice,
                    XRP(10000),
                    XRP(2),
                    rewardX,
                    true,
                    1,
                    aliceX,
                    signerXs[0]),
                onBehalfOf(attesterX),
                ter(tecNO_PERMISSION));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            envX(account_permission::accountPermissionSet(
                attesterX, bobX, {"XChainAddAccountCreateAttestation"}));
            envX.close();
            envX.require(balance(attesterX, attesterXBalance - drops(baseFee)));
            attesterXBalance = envX.balance(attesterX, XRP);

            envX(
                create_account_attestation(
                    bobX,
                    jvBridge,
                    alice,
                    XRP(10000),
                    XRP(2),
                    rewardX,
                    true,
                    1,
                    aliceX,
                    signerXs[0]),
                onBehalfOf(attesterX));
            envX.close();
            BEAST_EXPECT(envX.le(aliceX));
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            envX.require(
                balance(Account::master, doorXBalance - XRP(10000) - XRP(2)));
            envX.require(balance(aliceX, aliceXBalance + XRP(10000)));
            envX.require(balance(rewardX, rewardXBalance + XRP(2)));
            bobXBalance = envX.balance(bobX, XRP);
            doorXBalance = envX.balance(Account::master, XRP);
            aliceXBalance = envX.balance(aliceX, XRP);
            rewardXBalance = envX.balance(rewardX, XRP);
        }
        envX.memoize(aliceX);

        // XChainCreateClaimID
        {
            envX(
                xchain_create_claim_id(bobX, jvBridge, XRP(2), alice),
                onBehalfOf(carolX),
                ter(tecNO_PERMISSION));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            envX(account_permission::accountPermissionSet(
                carolX, bobX, {"XChainCreateClaimID"}));
            envX.close();
            envX.require(balance(carolX, carolXBalance - drops(baseFee)));
            carolXBalance = envX.balance(carolX, XRP);

            envX(
                xchain_create_claim_id(bobX, jvBridge, XRP(2), alice),
                onBehalfOf(carolX));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);
            BEAST_EXPECT(
                !!envX.le(keylet::xChainClaimID(STXChainBridge(jvBridge), 1)));
        }

        // XChainCommit
        {
            env(xchain_commit(bob, jvBridge, 1, XRP(20000), std::nullopt),
                onBehalfOf(alice),
                ter(tecNO_PERMISSION));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            bobBalance = env.balance(bob, XRP);

            env(account_permission::accountPermissionSet(
                alice, bob, {"XChainCommit"}));
            env.close();
            env.require(balance(alice, aliceBalance - drops(baseFee)));
            aliceBalance = env.balance(alice, XRP);

            env(xchain_commit(bob, jvBridge, 1, XRP(20000), std::nullopt),
                onBehalfOf(alice));
            env.close();
            env.require(balance(bob, bobBalance - drops(baseFee)));
            env.require(balance(alice, aliceBalance - XRP(20000)));
            env.require(balance(door, doorBalance + XRP(20000)));
            bobBalance = env.balance(bob, XRP);
            aliceBalance = env.balance(alice, XRP);
            doorBalance = env.balance(door, XRP);
        }

        // XChainAddClaimAttestation
        {
            envX(
                claim_attestation(
                    bobX,
                    jvBridge,
                    alice,
                    XRP(20000),
                    rewardX,
                    true,
                    1,
                    std::nullopt,
                    signerX),
                onBehalfOf(attesterX),
                ter(tecNO_PERMISSION));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            envX(account_permission::accountPermissionSet(
                attesterX, bobX, {"XChainAddClaimAttestation"}));
            envX.close();
            envX.require(balance(attesterX, attesterXBalance - drops(baseFee)));
            attesterXBalance = envX.balance(attesterX, XRP);

            envX(
                claim_attestation(
                    bobX,
                    jvBridge,
                    alice,
                    XRP(20000),
                    rewardX,
                    true,
                    1,
                    std::nullopt,
                    signerX),
                onBehalfOf(attesterX));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);
        }

        // XChainClaim
        {
            envX(
                xchain_claim(bobX, jvBridge, 1, XRP(20000), aliceX),
                onBehalfOf(carolX),
                ter(tecNO_PERMISSION));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            bobXBalance = envX.balance(bobX, XRP);

            envX(account_permission::accountPermissionSet(
                carolX, bobX, {"XChainClaim"}));
            envX.close();
            envX.require(balance(carolX, carolXBalance - drops(baseFee)));
            carolXBalance = envX.balance(carolX, XRP);

            envX(
                xchain_claim(bobX, jvBridge, 1, XRP(20000), aliceX),
                onBehalfOf(carolX));
            envX.close();
            envX.require(balance(bobX, bobXBalance - drops(baseFee)));
            envX.require(balance(carolX, carolXBalance - XRP(2)));
            envX.require(balance(Account::master, doorXBalance - XRP(20000)));
            envX.require(balance(rewardX, rewardXBalance + XRP(2)));
            envX.require(balance(aliceX, aliceXBalance + XRP(20000)));
            bobXBalance = envX.balance(bobX, XRP);
            carolXBalance = envX.balance(carolX, XRP);
            doorXBalance = envX.balance(Account::master, XRP);
            rewardXBalance = envX.balance(rewardX, XRP);
            aliceXBalance = envX.balance(aliceX, XRP);
            BEAST_EXPECT(
                !envX.le(keylet::xChainClaimID(STXChainBridge(jvBridge), 1)));
        }

        env.require(balance(door, doorBalance));
        env.require(balance(alice, aliceBalance));
        env.require(balance(bob, bobBalance));
        envX.require(balance(Account::master, doorXBalance));
        envX.require(balance(attesterX, attesterXBalance));
        envX.require(balance(signerX, signerXBalance));
        envX.require(balance(rewardX, rewardXBalance));
        envX.require(balance(aliceX, aliceXBalance));
        envX.require(balance(bobX, bobXBalance));
        envX.require(balance(carolX, carolXBalance));
    }

    // void
    // testAccountDelete(FeatureBitset features)
    // {
    //     testcase("test AccountDelete");
    //     using namespace jtx;

    //     // test create trustline
    //     {
    //         Env env(*this, features);
    //         Account gw{"gw"};
    //         Account alice{"alice"};
    //         Account bob{"bob"};
    //         env.fund(XRP(1'000), gw, alice, bob);

    //         env(account_permission::accountPermissionSet(
    //             bob, alice, {"TrustSet"}));
    //     }
    // }

    void
    testPayment(FeatureBitset features)
    {
        testcase("test payment");
        using namespace jtx;

        {
            Env env(*this, features);
            Account alice{"alice"};
            Account bob{"bob"};
            Account carol{"carol"};
            env.fund(XRP(10000), alice, bob, carol);
            env.close();

            env(account_permission::accountPermissionSet(
                alice, bob, {"Payment"}));
            env.close();

            std::cout << " ------ " << std::endl;

            // bob send himself 50XRP on behalf of alice
            // env(pay(bob, bob, XRP(50)), onBehalfOf(alice));
            env(pay(alice, bob, XRP(50)));
        }
    }

    void
    run() override
    {
        FeatureBitset const all{jtx::supported_amendments()};
        // testFeatureDisabled(all - featureAccountPermission);
        // testInvalidRequest(all);
        // testPermissionCRUD(all);
        // testAccountDelete(all);
        // testAMM(all);
        // testCheck(all);
        // testClawback(all);
        // testCrendentials(all);
        // testDepositPreauth(all);
        // testDID(all);
        // testEscrow(all);
        // testMPToken(all);
        // testNFToken(all);
        // testOracle(all);
        testPayment(all);
        // testTrustSet(all);
        // testXChain(all);
    }
};
BEAST_DEFINE_TESTSUITE(AccountPermission, app, ripple);
}  // namespace test
}  // namespace ripple
