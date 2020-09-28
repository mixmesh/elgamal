-module(unit_test_elgamal).
-export([start/0]).

-include("../include/elgamal.hrl").

start() ->
    {Pk, Sk} = elgamal:generate_key_pair(),
    
    %% ==== Test multiplicative ElGamal encryption ====

    Plaintext = crypto:strong_rand_bytes(?MAX_MESSAGE_SIZE),
    Ciphertext = elgamal:encrypt(Plaintext, Pk),
    Plaintext = elgamal:decrypt(Ciphertext, Sk),

    %% ==== Test additive ElGamal encryption ====
    
    %% NOTE: The plaintext can currently not be longer than 2 bytes when
    %% performing additive ElGamal encryption, i.e. solving the discrete
    %% logarithm using brute force takes too long time for larger
    %% plaintexts. It must be possible to support 160 bits plaintexts,
    %% i.e. the SHA1 key needed by crypto:mac^4 when computing
    %% the HMAC (see Spiridon) is 20 bytes. This is a show stopper! 
    ShortPlaintext = crypto:strong_rand_bytes(2),
    ShortCiphertext = elgamal:modified_encrypt(ShortPlaintext, Pk),
    %% Takes ~5 seconds on my machine
    ShortPlaintext = elgamal:modified_decrypt(ShortCiphertext, Sk),

    %% ==== Test encryption as introduced by Spiridon ====

    ManyPlaintexts = [crypto:strong_rand_bytes(?MAX_MESSAGE_SIZE),
                      crypto:strong_rand_bytes(?MAX_MESSAGE_SIZE)],
    ManyCiphertexts = elgamal:uencrypt(ManyPlaintexts, Pk),
    ManyPlaintexts = elgamal:udecrypt(ManyCiphertexts, Sk),
    %% NOTE: Here we perform 10 re-encryptions and the problem now is
    %% that the randomized ciphertext steadily grows in size for each
    %% randomization. Why? This is a showstopper! 
    many_urandomize(ManyPlaintexts, ManyCiphertexts, Sk, 10).

many_urandomize(Plaintexts, Ciphertexts, Sk, N) ->
  case N of
      0 ->
          ok;
      _ ->
          RandomizedCiphertexts = elgamal:urandomize(Ciphertexts),
          io:format("Randomized ciphertext size: ~w\n",
                    [size(term_to_binary(RandomizedCiphertexts))]),
          Plaintexts = elgamal:udecrypt(RandomizedCiphertexts, Sk),
          many_urandomize(Plaintexts, RandomizedCiphertexts, Sk, N - 1)
  end.
