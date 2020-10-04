-module(test_belgamal).
-export([start/0]).

start() ->
  {Pk, Sk} = elgamal:generate_key_pair(),
  Plaintext = crypto:strong_rand_bytes(64),
  Ciphertext = belgamal:encrypt(Plaintext, Pk),
  Plaintext = belgamal:decrypt(Ciphertext, Sk),
  Plaintext2 = crypto:strong_rand_bytes(100000),
  Ciphertext2 = belgamal:uencrypt(Plaintext2, Pk),
  Plaintext2 = belgamal:udecrypt(Ciphertext2, Sk),
  many_randomizations(Plaintext2, Ciphertext2, Sk, 10).

many_randomizations(_Plaintext, _Ciphertext, _Sk, 0) ->
    ok;
many_randomizations(Plaintext, Ciphertext, Sk, N) ->
    RandomizedCiphertext = belgamal:urandomize(Ciphertext),
    io:format("SIZE: ~w\n", [size(RandomizedCiphertext)]),
    Plaintext = belgamal:udecrypt(RandomizedCiphertext, Sk),
    many_randomizations(Plaintext, RandomizedCiphertext, Sk, N - 1).
