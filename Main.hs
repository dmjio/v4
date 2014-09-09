{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module V4 
    ( -- * Types
      Method           (..)  
    , CanonicalRequest (..)
    , SecretKey        (..)
    , Region
    , Service
    , Params
      -- * API Functions
    , createSignature
    )
    where

import           Control.Applicative
import           Crypto.Hash            (Digest)
import           Crypto.Hash.SHA256
import           Crypto.MAC.HMAC
import           Data.ByteString        (ByteString)
import           Data.ByteString.Base16 (encode)
import qualified Data.ByteString.Char8  as B8
import           Data.Char
import           Data.String
import           Data.Monoid
import           Data.Time
import           Data.Function
import           Data.List

import           System.IO.Unsafe
import           System.Locale

type Region  = ByteString
type Service = ByteString
type Params  = [(ByteString, ByteString)]

newtype SecretKey = 
    SecretKey ByteString deriving (Eq, Show)

data Method = 
    GET 
  | PUT
  | POST
  | DELETE
    deriving (Show, Eq)

data CanonicalRequest = CanonicalRequest {
      canonicalRequestMethod  :: Method
    , canonicalURI            :: ByteString
    , canonicalQueryString    :: ByteString
    , canonicalHeaders        :: Params
    , canonicalSignedHeaders  :: [ByteString]
    , canonicalRequestActions :: Params
} deriving (Show, Eq)

secret :: ByteString
secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

createSignature
    :: SecretKey        -- ^ Your AWS Secret Key
    -> CanonicalRequest -- ^ The Canonical Request 
    -> Region           -- ^ The region you wish to use to perform this AWS operation
    -> Service          -- ^ The service you'd like to use to perfrom this AWS operation
    -> IO ByteString
createSignature
    secretKey
    canonicalRequest
    region
    service
    = encode <$> liftA2 hmacSHA256 key string
  where key    = signingKey secretKey region service
        string = stringToSign canonicalRequest region service

stringToSign
    :: CanonicalRequest
    -> Region
    -> Service
    -> IO ByteString
stringToSign
    canonicalRequest
    region
    service = do
      smallDate <- dateTime
      longDate  <- isoDate
      let credScope = B8.intercalate "/" [
                        smallDate
                      , region
                      , service
                      , "aws4_request"
                      ]
      return $ B8.intercalate "\n" [
                  "AWS4-HMAC-SHA256"
                 , "20110909T233600Z"
                 , credScope
                 , hexEncode $ createCanonical canonicalRequest
                 ]
signingKey
    :: SecretKey
    -> Region
    -> Service
    -> IO ByteString
signingKey
  (SecretKey secretKey)
  region
  service = do
    date <- dateTime
    return $ foldr hmacSHA256 ("AWS4" <> secretKey) [
                 date
               , region
               , service
               , "aws4_request"
               ]

createCanonical
    :: CanonicalRequest
    -> ByteString
createCanonical 
    CanonicalRequest {..}
    = B8.intercalate "\n" [ method
                          , uri
                          , queryString 
                          , headers
                          , signedHeaders
                          , hexEncode requestActions
                          ]
  where method         = B8.pack $ show canonicalRequestMethod
        uri            = canonicalURI
        queryString    = canonicalQueryString
        headers        = foldr (\(k,v) c -> 
                                    B8.concat [ 
                                           B8.map toLower k 
                                          , ":", v, "\n", c 
                                          ]) mempty (sortBy (compare `on` fst) canonicalHeaders)
        signedHeaders  = B8.intercalate ";" canonicalSignedHeaders
        requestActions = toQueryString canonicalRequestActions

hmacSHA256
    :: ByteString
    -> ByteString
    -> ByteString
hmacSHA256 = hmac hash 64

hexEncode
    :: ByteString
    -> ByteString
hexEncode = B8.map toLower . encode . hash

dateTime :: IO ByteString
dateTime = fmt <$> getCurrentTime
  where fmt = B8.pack . formatTime defaultTimeLocale "%Y%m%d"

isoDate :: IO ByteString
isoDate = iso8601 <$> getCurrentTime
  where iso8601 = B8.pack . formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

toQueryString :: [(ByteString, ByteString)] -> ByteString
toQueryString [] = ""
toQueryString ((x,y):[]) = x <> "=" <> y
toQueryString ((x,y):xs) = x <> "=" <> y <> "&" <> toQueryString xs

