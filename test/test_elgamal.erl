-module(test_elgamal).
-export([start/0]).
-export([benchmark_encrypt/0]).
-export([benchmark_decrypt/0]).
-export([benchmark_randomize/0]).
-include("../include/elgamal.hrl").

start() ->
    BKeys = {BPk, BSk} = elgamal:generate_key_pair(<<"Bob">>),
    AKeys = {APk, ASk} = elgamal:generate_key_pair(<<"Alice">>),

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

    %% Run som benchmarks

    benchmark_encrypt(Message, AKeys, BKeys),
    benchmark_decrypt(Message, AKeys, BKeys),
    benchmark_randomize(Message, AKeys, BKeys),

    ok.

%%
%% To messure the encryption speed sets the limit on how many
%% connection we may have on the target platform
%%
benchmark_encrypt() ->
    BKeys = elgamal:generate_key_pair(<<"Bob">>),
    AKeys = elgamal:generate_key_pair(<<"Alice">>),
    Message = <<"This crypto system is secure as hell.">>,
    benchmark_encrypt(Message, AKeys, BKeys).

benchmark_encrypt(Message, {APk,_},{_,BSk}) ->
    BlobFromBob = elgamal:uencrypt(Message, APk, BSk),
    io:format("blob size = ~w\n", [byte_size(BlobFromBob)]),
    N = 100,
    T0 = erlang:monotonic_time(),
    benchmark_encrypt_n(Message, APk, BSk, N),
    T1 = erlang:monotonic_time(),
    Time = erlang:convert_time_unit(T1-T0,native,microsecond),
    io:format("encrypt ~.2f messages/s\n", [N/(Time/1000000)]),
    ok.

benchmark_encrypt_n(_Message, _APk, _Bsk, 0) ->
    ok;
benchmark_encrypt_n(Message, APk, BSk, I) ->
    _Blob = elgamal:uencrypt(Message, APk, BSk),
    benchmark_encrypt_n(Message, APk, BSk, I-1).

%%
%% To messure the decryption speed sets the limit on how many
%% connection we may have on the target platform
%%
benchmark_decrypt() ->
    BKeys = elgamal:generate_key_pair(<<"Bob">>),
    AKeys = elgamal:generate_key_pair(<<"Alice">>),
    Message = <<"This crypto system is secure as hell.">>,
    benchmark_decrypt(Message, AKeys, BKeys).

benchmark_decrypt(Message, {APk,ASk}, {_BPk,BSk}) ->
    BlobFromBob = elgamal:uencrypt(Message, APk, BSk),
    {_,_Signature,Message} = elgamal:udecrypt(BlobFromBob, ASk),
    N = 100,
    T0 = erlang:monotonic_time(),
    benchmark_decrypt_n(BlobFromBob, ASk, N),
    T1 = erlang:monotonic_time(),
    Time = erlang:convert_time_unit(T1-T0,native,microsecond),
    io:format("decrypt ~.2f messages/s\n", [N/(Time/1000000)]),
    ok.

benchmark_decrypt_n(_Message, _ASk, 0) ->
    ok;
benchmark_decrypt_n(Message, ASk, I) ->
    {_From,_Signature,_Message} = elgamal:udecrypt(Message, ASk),
    benchmark_decrypt_n(Message, ASk, I-1).

%%
%% To messure the randomize speed sets the limit on how many
%% connection we may have on the target platform
%%
benchmark_randomize() ->
    BKeys = elgamal:generate_key_pair(<<"Bob">>),
    AKeys = elgamal:generate_key_pair(<<"Alice">>),
    Message = <<"This crypto system is secure as hell.">>,
    benchmark_randomize(Message, AKeys, BKeys).

benchmark_randomize(Message, {APk,ASk}, {BPk,BSk}) ->
    BlobFromBob = elgamal:uencrypt(Message, APk, BSk),
    N = 100,
    T0 = erlang:monotonic_time(),
    ScrambledBlob = benchmark_randomize_n(BlobFromBob, N),
    T1 = erlang:monotonic_time(),
    Time = erlang:convert_time_unit(T1-T0,native,microsecond),
    {<<"Bob">>,Signature,Message} = elgamal:udecrypt(ScrambledBlob, ASk),
    io:format("randomize ~.2f messages/s\n", [N/(Time/1000000)]),
    true = elgamal:verify(Signature, Message, BPk),
    ok.

benchmark_randomize_n(Blob, 0) ->
    Blob;
benchmark_randomize_n(Blob, I) ->
    Blob1 = elgamal:urandomize(Blob),
    benchmark_randomize_n(Blob1, I-1).





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
