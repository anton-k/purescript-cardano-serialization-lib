module Main (main) where

import Lib

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

exportPursTypes = do
  cs <- getClasses
  writeFile "types.purs" (unlines $ fmap typePurs $ classTypes cs)


exporFuns = do
  fs <- funs <$> readFile file
  mapM_ putStrLn $ fmap funPurs fs
  putStrLn "\n"
  mapM_ putStrLn $ fmap typePurs $ funsTypes fs
  putStrLn "\n"
  mapM_ putStrLn $ fmap funJs fs

exportPursClasses = do
  cs <- getClasses
  writeFile "class.purs" (unlines $ fmap classPurs cs)

exportJsClasses = do
  cs <- getClasses
  writeFile "class.js" (unlines $ fmap classJs cs)

getClasses = fmap parseClass . toClassParts  <$> readFile file
