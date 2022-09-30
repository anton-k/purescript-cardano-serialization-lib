module Csl(
  module Csl,
  module X
) where

import Csl.Gen as X
import Csl.Parse as X
import Csl.Types as X

exportPursTypes = do
  cs <- getClasses
  writeFile "types.purs" (unlines $ fmap typePurs $ classTypes cs)

exporFuns = do
  fs <- getFuns
  mapM_ putStrLn $ fmap funPurs fs
  putStrLn "\n"
  mapM_ putStrLn $ fmap typePurs $ funsTypes fs
  putStrLn "\n"
  mapM_ putStrLn $ fmap funJs fs

exportPursClasses = do
  cs <- getClasses
  exportFile "class.purs" (unlines $ fmap classPurs cs)

exportJsClasses = do
  cs <- getClasses
  exportFile "class.js" (unlines $ fmap classJs cs)

getFuns = funs <$> readFile file
getClasses = fmap parseClass . toClassParts  <$> readFile file

-------------------------------------------------------------------------------------
-- utils

exportFile :: FilePath -> String -> IO ()
exportFile name content = writeFile ("output/" <> name) content

