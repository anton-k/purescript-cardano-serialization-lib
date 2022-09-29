-- | Dynamic API for typescript export
module Main
  ( main
  ) where

import Prelude
import Effect (Effect)
import Effect.Console (logShow)
import Csl as Csl

--------------------------------------------------------
-- console tests

main :: Effect Unit
main = do
  logShow "hi"
  logShow $ max (Csl.bigNum.fromStr "1000" * Csl.bigNum.fromStr "2") one
  logShow $ Csl.value.toJson $ Csl.value.new (Csl.bigNum.fromStr "1000")

{-
txBuildExample :: Effect Unit
txBuildExample = do
  let
    addr = getRight $ byronFromBase58
      "Ae2tdPwUPEZLs4HtbuNey7tK4hTKrwNwYtGqp7bDfCy2WdR3P6735W5Yfpe"
    hash = getJust $ Csl.fromHex
      "488afed67b342d41ec08561258e210352fba2ac030c98a8199bc22ec7a27ccf1"
  builder <- newTxBuilder
  setFee builder (bigNumFromString "10")
  setTtl builder (bigNumFromString "100000")
  addBootstrapInput builder addr (initTxIn hash 0) (initValue (bigNumFromString "3000000"))
  addOutput builder (initTxOut (byronToAddress addr) (initValue (bigNumFromString "10000000")))
  setCollateral builder =<< do
    ins <- TxIns.newTxInsBuilder
    TxIns.addBootstrapInput ins addr (initTxIn hash 0) (initValue (bigNumFromString "300000"))
    pure ins

  logShow $ fullSize builder
  txBody <- buildTxBody builder
  logShow $ hashTx txBody
  -}
