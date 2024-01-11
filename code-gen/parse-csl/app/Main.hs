module Main (main) where

import           Csl
import           Data.Functor       ((<&>))
import           Data.Maybe         (mapMaybe)
import           System.Directory   (createDirectoryIfMissing)
import           System.Environment (getArgs)
import           System.FilePath    (takeDirectory)
import           System.IO          (IOMode (..), withFile)

main :: IO ()
main = do
  exportPath <- (<> "/") . head <$> getArgs
  jsLibHeader <- readFile "./fixtures/Lib.js"
  importsCode <- readFile "./fixtures/imports.purs"
  pursInternalLib <- readFile "./fixtures/Internal.purs"
  funs <- getFuns
  classes <- getClasses
  print funs
  -- print classes
  let
    filteredClasses = classes <&> \(Class name methods) -> Class name $
      filter (not . isCommon . method'fun) methods
    nonCommonFuns = filter (not . isCommon) funs
    funsJsCode = unlines $ funJs <$> nonCommonFuns
    funsPursCode = unlines $ funPurs <$> nonCommonFuns
    classesPursCode = unlines $ classPurs <$> classes
    classesJsCode = unlines $ classJs <$> filteredClasses
    exportsPursCode = exportListPurs nonCommonFuns filteredClasses
  createDirectoryIfMissing True $ takeDirectory $ exportPath <> "/"
  createDirectoryIfMissing True $ takeDirectory $ exportPath <> "/Lib/"
  writeFile (exportPath <> "Lib.purs") $ unlines
    [ pursLibHeader ++ exportsPursCode ++ "\n  ) where"
    , importsCode
    , ""
    , "-- functions"
    , funsPursCode
    , ""
    , "-- classes"
    , ""
    , classesPursCode
    ]
  writeFile (exportPath <> "Lib.js") $ unlines
    [ jsLibHeader
    , classesJsCode
    , funsJsCode
    ]
  writeFile (exportPath <> "Lib/Internal.purs") pursInternalLib

pursLibHeader = "module Cardano.Serialization.Lib\n  ( "
