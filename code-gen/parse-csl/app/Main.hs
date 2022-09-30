module Main (main) where

import Csl

main :: IO ()
main = do
  exportJsClasses
{-
  cs <- getClasses
  let a = head $ filter ((== "Assets") . class'name) cs
      b = head $ filter ((== "insert"). fun'name . method'fun) $ class'methods a
  putStrLn $ toType $ fun'res $ method'fun b
  print a
-}


