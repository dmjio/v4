{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Applicative
import           Crypto.Hash            (Digest)
import           Crypto.Hash.SHA256
import           Crypto.MAC.HMAC
import           Data.ByteString        (ByteString)
import           Data.ByteString.Base16 (encode)
import qualified Data.ByteString.Char8  as B8
import           Data.Char
import           Data.Monoid
import           Data.Time
import           System.IO.Unsafe
import           System.Locale

main :: IO ()
main = putStrLn "testing aws..."

-- | Step 1: create canonical request
req :: ByteString
req = B8.intercalate "\n" [ method
                          , uri
                          , queryString
                          , headers
                          , signedHeaders
                          , hexEncode (hash hexHashPayload)
                          ]
  where method         = "POST"
        uri            = "/"
        queryString    = ""
        headers        = "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nx-amz-date:20110909T233600Z\n"
        signedHeaders  = "content-type;host;x-amz-date"
        hexHashPayload = "Action=ListUsers&Version=2010-05-08"

hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 secret msg = hmac hash 64 secret msg

lower :: ByteString -> ByteString
lower = B8.map toLower

hexEncode :: ByteString -> ByteString
hexEncode = lower . encode

removeWhiteSpace :: ByteString -> ByteString
removeWhiteSpace = B8.filter (/=' ')

-- Step 2: hash canonical
hashedCanonical :: ByteString
hashedCanonical = hexEncode (hash req)

dateTime :: IO ByteString
dateTime = fmt <$> getCurrentTime
  where fmt = B8.pack . formatTime defaultTimeLocale "%Y%m%d"

isoDate :: IO ByteString
isoDate = iso8601 <$> getCurrentTime
  where iso8601 = B8.pack . formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

-- Step 3: Create string to sign
stringToSign :: ByteString
stringToSign = B8.intercalate "\n" [ algo
                                   , reqDate
                                   , credScope
                                   , hashedCanonicalReq
                                   ]
  where algo               = "AWS4-HMAC-SHA256"
        reqDate            = "20110909T233600Z"
        credScope          = B8.intercalate "/" [ "20110909"
                                                , "us-east-1"
                                                , "iam"
                                                , "aws4_request"
                                                ]
        hashedCanonicalReq = hashedCanonical

secret :: ByteString
secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

signingKey :: ByteString
signingKey = kSigning
  where kDate    = hmacSHA256 ("AWS4" <> secret) "20110909"
        kRegion  = hmacSHA256 kDate    "us-east-1"
        kService = hmacSHA256 kRegion  "iam"
        kSigning = hmacSHA256 kService "aws4_request"

signature :: ByteString
signature = encode $ hmacSHA256 signingKey stringToSign


