-module(test_elgamal).
-export([start/0]).

-include("../include/elgamal.hrl").

start() ->
    {BPk, BSk} = elgamal:generate_key_pair(<<"Bob">>),
    {APk, ASk} = elgamal:generate_key_pair(<<"Alice">>),

    %% ==== Test multiplicative ElGamal encryption ====

    Plaintext = crypto:strong_rand_bytes(?SEGMENT_SIZE),
    Ciphertext = elgamal:encrypt(Plaintext, APk),
    Plaintext = elgamal:decrypt(Ciphertext, ASk),

    %% ==== Test additive ElGamal encryption ====

    %% %% NOTE: The plaintext can currently not be longer than 2 bytes when
    %% %% performing additive ElGamal encryption, i.e. solving the discrete
    %% %% logarithm using brute force takes too long time for larger
    %% %% plaintexts. It must be possible to support 160 bits plaintexts,
    %% %% i.e. the SHA1 key needed by crypto:mac^4 when computing
    %% %% the HMAC (see Spiridon) is 20 bytes. This is a show stopper!
    %% ShortPlaintext = crypto:strong_rand_bytes(2),
    %% ShortCiphertext = elgamal:modified_encrypt(ShortPlaintext, APk),
    %% %% Takes ~5 seconds on my machine
    %% ShortPlaintext = elgamal:modified_decrypt(ShortCiphertext, ASk),

    %% ==== Test encryption as introduced by Spiridon ====

    ManyPlaintexts = [crypto:strong_rand_bytes(?SEGMENT_SIZE),
                      crypto:strong_rand_bytes(?SEGMENT_SIZE)],
    ManyCiphertexts = elgamal:uencrypt(ManyPlaintexts, APk),
    ManyPlaintexts = elgamal:udecrypt(ManyCiphertexts, ASk),
    %% NOTE: Here we perform 10 re-encryptions and the problem now is
    %% that the randomized ciphertext steadily grows in size for each
    %% randomization. Why? This is a showstopper!
    many_urandomize(ManyPlaintexts, ManyCiphertexts, ASk, 10),

    %% ==== Test encryption vith signature and verify

    %% Bob send message to Alice (APk) and sign it with BSk

    Message = <<"This crypto system is secure as hell.">>,
    BlobFromBob = elgamal:uencrypt(Message, APk, BSk),

    %% Alice receives a message using her secret key ASk
    {_BobsNym,Signature,Message} = elgamal:udecrypt(BlobFromBob, ASk),

    %% Alice looks up Bobs public key using Nym to search the public key store
    %% and verify that the message is indeed sent from Bob

    true = elgamal:verify(Signature, Message, BPk),

    ok.





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
