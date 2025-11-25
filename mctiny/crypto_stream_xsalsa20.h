#ifndef CRYPTO_STREAM_XSALSA20_H
#define CRYPTO_STREAM_XSALSA20_H

#include "tweetnacl.h"

// McTiny Constant Names -> TweetNaCl Constant Names
#define crypto_stream_xsalsa20_KEYBYTES crypto_stream_xsalsa20_tweet_KEYBYTES
#define crypto_stream_xsalsa20_NONCEBYTES crypto_stream_xsalsa20_tweet_NONCEBYTES

// McTiny Function -> TweetNaCl Function
// TweetNaCl's "crypto_stream_xor" IS XSalsa20
#define crypto_stream_xsalsa20_xor crypto_stream_xsalsa20_tweet_xor

#endif