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
#include <test/jtx/trust.h>
#include <xrpld/ledger/ApplyViewImpl.h>
#include <xrpl/basics/random.h>
#include <xrpl/json/to_string.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/jss.h>
#include <initializer_list>
namespace ripple {
namespace test {
class AMMClawback_test : public jtx::AMMTest
{
    void
    testInvalidRequest(FeatureBitset features)
    {
        testcase("test invalid request");
        using namespace jtx;

        // Test if the AMMAccount provided is not an AMM account. This should
        // return terNO_AMM error.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // gateway send invalid request
            // by passing alice account as AMMAccount, this should return
            // terNO_AMM
            env(ammClawback(
                    gw, alice, USD, std::nullopt, alice.id(), std::nullopt),
                ter(terNO_AMM));
        }

        // Test if the issuer field and holder field is the same. This should
        // return temMALFORMED error.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // issuer can not clawback from himself
            env(ammClawback(
                    gw, gw, USD, std::nullopt, amm.ammAccount(), std::nullopt),
                ter(temMALFORMED));
        }

        // Test if the Asset field matches the Account field.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // The Asset's issuer field is alice, while the Account field is gw.
            // This should return temBAD_ASSET_ISSUER because they do not match.
            env(ammClawback(
                    gw,
                    alice,
                    Issue{gw["USD"].currency, alice.id()},
                    std::nullopt,
                    amm.ammAccount(),
                    std::nullopt),
                ter(temBAD_ASSET_ISSUER));
        }

        // Test if the Amount field matches the Asset field.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // The Asset's issuer subfield is gw account and Amount's issuer
            // subfield is alice account. Return temBAD_ASSET_AMOUNT because
            // they do not match.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, alice.id()}, 1},
                    amm.ammAccount(),
                    std::nullopt),
                ter(temBAD_ASSET_AMOUNT));
        }

        // Test if the Amount is invalid, which is less than zero.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // Return temBAD_AMOUNT if the Amount value is less than 0.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, -1},
                    amm.ammAccount(),
                    std::nullopt),
                ter(temBAD_AMOUNT));
        }

        // Test if the issuer did not set asfAllowTrustLineClawback, AMMClawback
        // transaction is prohibited.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();
            env.require(balance(alice, gw["USD"](100)));
            env.require(balance(gw, alice["USD"](-100)));

            // create AMM pool of XRP/USD
            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // If asfAllowTrustLineClawback is not set, the issuer is not
            // allowed to send the AMMClawback transaction.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    std::nullopt,
                    amm.ammAccount(),
                    std::nullopt),
                ter(tecNO_PERMISSION));
        }

        // Test if the Asset being clawed back does not exist in the AMM pool.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            // create AMM pool of XRP/USD
            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // Return tecNO_PERMISSION because the Asset EUR does not
            // match AMM pool assets XRP/USD.
            env(ammClawback(
                    gw,
                    alice,
                    gw["EUR"],
                    std::nullopt,
                    amm.ammAccount(),
                    std::nullopt),
                ter(tecNO_PERMISSION));
        }

        // Test if tfClawTwoAssets is set when the two assets in the AMM pool
        // are not issued by the same issuer.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(10000), gw, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 100 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(1000), alice);
            env(pay(gw, alice, USD(100)));
            env.close();

            // create AMM pool of XRP/USD
            AMM amm(env, gw, XRP(100), USD(100), ter(tesSUCCESS));

            // Return tecNO_PERMISSION because the issuer set tfClawTwoAssets,
            // but the issuer only issues USD in the pool. The issuer is not
            // allowed to set tfClawTwoAssets flag if he did not issue both
            // assts in the pool.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    std::nullopt,
                    amm.ammAccount(),
                    tfClawTwoAssets),
                ter(tecNO_PERMISSION));
        }
    }

    void
    testAMMClawbackSpecificAmount(FeatureBitset features)
    {
        testcase("test AMMClawback specific amount");
        using namespace jtx;

        // Test AMMClawback for USD/EUR pool. The assets are issued by different
        // issuer. Claw back USD, and EUR goes back to the holder.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account gw2{"gateway2"};
            Account alice{"alice"};
            env.fund(XRP(1000000), gw, gw2, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 3000 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(100000), alice);
            env(pay(gw, alice, USD(3000)));
            env.close();
            env.require(balance(gw, alice["USD"](-3000)));
            env.require(balance(alice, gw["USD"](3000)));

            // gateway2 issues 3000 EUR to Alice
            auto const EUR = gw2["EUR"];
            env.trust(EUR(100000), alice);
            env(pay(gw2, alice, EUR(3000)));
            env.close();
            env.require(balance(gw2, alice["EUR"](-3000)));
            env.require(balance(alice, gw2["EUR"](3000)));

            // Alice creates AMM pool of EUR/USD
            AMM amm(env, alice, EUR(1000), USD(2000), ter(tesSUCCESS));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(2000), EUR(1000), IOUAmount{1414213562373095, -12}));

            // gw clawback 1000 USD from the AMM pool
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, 1000},
                    amm.ammAccount(),
                    std::nullopt),
                ter(tesSUCCESS));
            env.close();

            // Alice's initial balance for USD is 3000 USD. Alice deposited 2000
            // USD into the pool, then she has 1000 USD. And 1000 USD was clawed
            // back from the AMM pool, so she still has 1000 USD.
            env.require(balance(gw, alice["USD"](-1000)));
            env.require(balance(alice, gw["USD"](1000)));

            // Alice's initial balance for EUR is 3000 EUR. Alice deposited 1000
            // EUR into the pool, 500 EUR was withdrawn proportionally. So she
            // has 2500 EUR now.
            env.require(balance(gw2, alice["EUR"](-2500)));
            env.require(balance(alice, gw2["EUR"](2500)));

            // 1000 USD and 500 EUR was withdrawn from the AMM pool, so the
            // current balance is 1000 USD and 500 EUR.
            BEAST_EXPECT(amm.expectBalances(
                USD(1000), EUR(500), IOUAmount{7071067811865475, -13}));

            // Alice has half of its initial lptokens Left.
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{7071067811865475, -13}));

            // gw clawback another 1000 USD from the AMM pool. The AMM pool will
            // be empty and get deleted.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, 1000},
                    amm.ammAccount(),
                    std::nullopt),
                ter(tesSUCCESS));
            env.close();

            // Alice should still has 1000 USD because gw clawed back from the
            // AMM pool.
            env.require(balance(gw, alice["USD"](-1000)));
            env.require(balance(alice, gw["USD"](1000)));

            // Alice should has 3000 EUR now because another 500 EUR was
            // withdrawn.
            env.require(balance(gw2, alice["EUR"](-3000)));
            env.require(balance(alice, gw2["EUR"](3000)));

            // amm is automatically deleted.
            BEAST_EXPECT(!amm.ammExists());
        }

        // Test AMMClawback for USD/XRP pool. Claw back USD, and XRP goes back to the holder.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account alice{"alice"};
            env.fund(XRP(1000000), gw, alice);
            env.close();
            
            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 3000 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(100000), alice);
            env(pay(gw, alice, USD(3000)));
            env.close();
            env.require(balance(gw, alice["USD"](-3000)));
            env.require(balance(alice, gw["USD"](3000)));

            // Alice creates AMM pool of XRP/USD
            AMM amm(env, alice, XRP(1000), USD(2000), ter(tesSUCCESS));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
                USD(2000), XRP(1000), IOUAmount{1414213562373095, -9}));

            auto aliceXrpBalance = env.balance(alice, XRP);
            // gw clawback 1000 USD from the AMM pool
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, 1000},
                    amm.ammAccount(),
                    std::nullopt),
                ter(tesSUCCESS));
            env.close();

            // Alice's initial balance for USD is 3000 USD. Alice deposited 2000
            // USD into the pool, then she has 1000 USD. And 1000 USD was clawed
            // back from the AMM pool, so she still has 1000 USD.
            env.require(balance(gw, alice["USD"](-1000)));
            env.require(balance(alice, gw["USD"](1000)));

            // Alice will get 500 XRP back. 
            BEAST_EXPECT(expectLedgerEntryRoot(env, alice, aliceXrpBalance + XRP(500)));

            // 1000 USD and 500 XRP was withdrawn from the AMM pool, so the
            // current balance is 1000 USD and 500 XRP.
            BEAST_EXPECT(amm.expectBalances(
                USD(1000), XRP(500), IOUAmount{7071067811865475, -10}));

            // Alice has half of its initial lptokens Left.
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{7071067811865475, -10}));

            // gw clawback another 1000 USD from the AMM pool. The AMM pool will
            // be empty and get deleted.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, 1000},
                    amm.ammAccount(),
                    std::nullopt),
                ter(tesSUCCESS));
            env.close();

            // Alice should still has 1000 USD because gw clawed back from the
            // AMM pool.
            env.require(balance(gw, alice["USD"](-1000)));
            env.require(balance(alice, gw["USD"](1000)));

            // Alice will get another 1000 XRP back.
            BEAST_EXPECT(expectLedgerEntryRoot(env, alice, aliceXrpBalance + XRP(1000)));

            // amm is automatically deleted.
            BEAST_EXPECT(!amm.ammExists());
        }
    }

    void
    testAMMClawbackExceedBalance(FeatureBitset features)
    {
        testcase("test AMMClawback specific amount which exceeds the current balance");
        using namespace jtx;

        // Test AMMClawback for USD/EUR pool. The assets are issued by different
        // issuer. Claw back USD for multiple times, and EUR goes back to the holder.
        // The last AMMClawback transaction exceeds the holder's USD balance in AMM pool.
        {
            Env env(*this, features);
            Account gw{"gateway"};
            Account gw2{"gateway2"};
            Account alice{"alice"};
            env.fund(XRP(1000000), gw, gw2, alice);
            env.close();

            // gateway sets asfAllowTrustLineClawback
            env(fset(gw, asfAllowTrustLineClawback));
            env.close();
            env.require(flags(gw, asfAllowTrustLineClawback));

            // gateway issues 6000 USD to Alice
            auto const USD = gw["USD"];
            env.trust(USD(100000), alice);
            env(pay(gw, alice, USD(6000)));
            env.close();
            env.require(balance(gw, alice["USD"](-6000)));
            env.require(balance(alice, gw["USD"](6000)));

            // gateway2 issues 6000 EUR to Alice
            auto const EUR = gw2["EUR"];
            env.trust(EUR(100000), alice);
            env(pay(gw2, alice, EUR(6000)));
            env.close();
            env.require(balance(gw2, alice["EUR"](-6000)));
            env.require(balance(alice, gw2["EUR"](6000)));

            // Alice creates AMM pool of EUR/USD
            AMM amm(env, alice, EUR(5000), USD(4000), ter(tesSUCCESS));
            env.close();

            BEAST_EXPECT(amm.expectBalances(
               USD(4000), EUR(5000), IOUAmount{4472135954999580, -12}));

            // gw clawback 1000 USD from the AMM pool
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, 1000},
                    amm.ammAccount(),
                    std::nullopt),
                ter(tesSUCCESS));
            env.close();

            // Alice's initial balance for USD is 6000 USD. Alice deposited 4000
            // USD into the pool, then she has 2000 USD. And 1000 USD was clawed
            // back from the AMM pool, so she still has 2000 USD.
            env.require(balance(gw, alice["USD"](-2000)));
            env.require(balance(alice, gw["USD"](2000)));

            // Alice's initial balance for EUR is 6000 EUR. Alice deposited 5000
            // EUR into the pool, 1250 EUR was withdrawn proportionally. So she
            // has 2500 EUR now.
            env.require(balance(gw2, alice["EUR"](-2250)));
            env.require(balance(alice, gw2["EUR"](2250)));

            // 1000 USD and 1250 EUR was withdrawn from the AMM pool, so the
            // current balance is 3000 USD and 3750 EUR.
            BEAST_EXPECT(amm.expectBalances(
                USD(3000), EUR(3750), IOUAmount{3354101966249685, -12}));

            // Alice has 3/4 of its initial lptokens Left.
            BEAST_EXPECT(
                amm.expectLPTokens(alice, IOUAmount{3354101966249685, -12}));

            // gw clawback another 500 USD from the AMM pool.
            env(ammClawback(
                    gw,
                    alice,
                    USD,
                    STAmount{Issue{gw["USD"].currency, gw.id()}, 500},
                    amm.ammAccount(),
                    std::nullopt),
                ter(tesSUCCESS));
            env.close();

            // Alice should still has 2000 USD because gw clawed back from the
            // AMM pool.
            env.require(balance(gw, alice["USD"](-2000)));
            env.require(balance(alice, gw["USD"](2000)));

            BEAST_EXPECT(amm.expectBalances(
                STAmount{USD, UINT64_C(2500000000000001), -12}, STAmount{EUR, UINT64_C(3125000000000001), -12}, IOUAmount{2795084971874738, -12}));

            BEAST_EXPECT(env.balance(alice, EUR) == STAmount(EUR, UINT64_C(2874999999999999), -12));
            // // amm is automatically deleted.
            // BEAST_EXPECT(!amm.ammExists());
        }
    }

public:
    void
    run() override
    {
        FeatureBitset const all{jtx::supported_amendments()};
        // testInvalidRequest(all);
        // testAMMClawbackSpecificAmount(all);
        testAMMClawbackExceedBalance(all);
    }
};
BEAST_DEFINE_TESTSUITE(AMMClawback, app, ripple);
}  // namespace test
}  // namespace ripple
