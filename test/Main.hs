{-# LANGUAGE OverloadedStrings #-}
module Main where

import V4
import Data.Time
import qualified Data.ByteString.Char8 as B8

main :: IO ()
main = B8.putStrLn =<< createSignature secretKey sampleDate sampleCanonical "us-east-1" "iam"

sampleDate :: UTCTime
sampleDate = read "2011-09-09 23:36:00 UTC"

sampleCanonical :: CanonicalRequest
sampleCanonical = CanonicalRequest POST "/" "" headers payload
  where
    headers = [ ("Content-Type","application/x-www-form-urlencoded; charset=utf-8")
              , ("Host","iam.amazonaws.com")
              , ("x-amz-date", isoDate sampleDate)
              ]
    payload = [ ("Action", "ListUsers")
              , ("Version", "2010-05-08")
              ]

secretKey :: SecretKey
secretKey = SecretKey "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
