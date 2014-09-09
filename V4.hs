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
import           Data.Time
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

createSignature
    :: SecretKey        -- ^ Your AWS Secret Key
    -> UTCTime          -- ^ TimeStamp for Request
    -> CanonicalRequest -- ^ The Canonical Request 
    -> Region           -- ^ The region you wish to use to perform this AWS operation
    -> Service          -- ^ The service you'd like to use to perfrom this AWS operation
    -> ByteString
createSignature
    secretKey
    time
    canonicalRequest
    region
    service = encode $ hmacSHA256 key string
  where key    = signingKey secretKey region service time
        string = stringToSign canonicalRequest time region service 

stringToSign
    :: CanonicalRequest
    -> UTCTime
    -> Region
    -> Service
    -> ByteString
stringToSign
    canonicalRequest
    time
    region
    service = 
      let smallDate = dateTime time
          longDate  = isoDate time
          credScope = B8.intercalate "/" [
                        smallDate
                      , region
                      , service
                      , "aws4_request"
                      ]
      in B8.intercalate "\n" [
                  "AWS4-HMAC-SHA256"
                 , longDate
                 , credScope
                 , hexEncode $ createCanonical canonicalRequest
                 ]
signingKey
    :: SecretKey
    -> Region
    -> Service
    -> UTCTime
    -> ByteString
signingKey
  (SecretKey secretKey)
  region
  service
  time = 
    let date = dateTime time
    in foldr hmacSHA256 ("AWS4" <> secretKey) [
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

dateTime
    :: UTCTime
    -> ByteString
dateTime = B8.pack . formatTime defaultTimeLocale "%Y%m%d"

isoDate
    :: UTCTime
    -> ByteString
isoDate = B8.pack . formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

toQueryString :: [(ByteString, ByteString)] -> ByteString
toQueryString [] = ""
toQueryString ((x,y):[]) = x <> "=" <> y
toQueryString ((x,y):xs) = x <> "=" <> y <> "&" <> toQueryString xs

