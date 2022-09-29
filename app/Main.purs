-- | Dynamic API for typescript export
module Main
  ( main
  ) where

import Prelude
import Effect (Effect)
import Effect.Console (logShow)
import Csl as Csl
import Csl.Class as Csl

--------------------------------------------------------
-- console tests

main :: Effect Unit
main = do
  logShow "hi"
  logShow $ max (Csl.bigNum.fromStr "1000" * Csl.bigNum.fromStr "2") one
  logShow $ Csl.value.toJson $ Csl.value.new (Csl.bigNum.fromStr "1000")
  txBuildExample


txBuildExample :: Effect Unit
txBuildExample = do
  let
    addr = Csl.byronAddress.fromBase58
      "Ae2tdPwUPEZLs4HtbuNey7tK4hTKrwNwYtGqp7bDfCy2WdR3P6735W5Yfpe"
    hash = Csl.txHash.fromHex
      "488afed67b342d41ec08561258e210352fba2ac030c98a8199bc22ec7a27ccf1"
  let config = Csl.txBuilderConfigBuilder.build Csl.txBuilderConfigBuilder.new
  builder <- Csl.txBuilder.new config
  Csl.txBuilder.setFee builder (Csl.bigNum.fromStr "10")
  Csl.txBuilder.setTtlBignum builder (Csl.bigNum.fromStr "100000")
  Csl.txBuilder.addBootstrapIn builder addr (Csl.txIn.new hash 0.0) (Csl.value.new (Csl.bigNum.fromStr "3000000"))
  Csl.txBuilder.addOut builder (Csl.txOut.new (Csl.byronAddress.toAddress addr) (Csl.value.new (Csl.bigNum.fromStr "10000000")))
  Csl.txBuilder.setCollateral builder =<< do
    ins <- Csl.txInsBuilder.new
    Csl.txInsBuilder.addBootstrapIn ins addr (Csl.txIn.new hash 0.0) (Csl.value.new (Csl.bigNum.fromStr "300000"))
    pure ins

  logShow $ Csl.txBuilder.fullSize builder
  let txBody = Csl.txBuilder.build builder
  logShow $ Csl.txHash.toHex $ Csl.hashTx txBody

