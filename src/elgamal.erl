-module(elgamal).
-export([generate_encryption_factors/1]).
-export([generate_key_pair/0]).
-export([encrypt/2, decrypt/2]).
-export([modified_encrypt/2, modified_decrypt/2]).
-export([uencrypt/2, udecrypt/2, urandomize/1]).

-include("elgamal.hrl").

%% This module implements multiplicative *and* additive ElGamal
%% encryption as described in "An Anonymous Messaging System for Delay
%% Tolerant Networks" by Spiridon Bakiras et al. (available locally).
%% Multiplicative ElGamal encryption is also described in general
%% terms in https://en.wikipedia.org/wiki/ElGamal_encryption.

%% Exported: generate_encryption_factors

generate_encryption_factors(Len) ->
    P = mpz:generate_safe_prime(Len),
    Q = (P - 1) div 2,
    G = new_generator(Q, P),
    {P, Q, G}.

new_generator(Q, P) ->
    G = crypto:rand_uniform(1, P),
    case mpz:powm(G, Q, P) == 1 andalso mpz:pow_ui(G, 2) /= 1 of
        true ->
            G;
        false ->
            new_generator(Q, P)
    end.

%% Exported: generate_key_pair

generate_key_pair() ->
    X = crypto:rand_uniform(1, ?Q),
    H = mpz:powm(?G, X, ?P),
    {#pk{h = H}, #sk{x = X}}.

%% Exported: encrypt (multiplicative ElGamal encryption)

encrypt(Plaintext, #pk{h = H}) ->
    M = binary:decode_unsigned(Plaintext),
    R = crypto:rand_uniform(1, ?Q),
    true = M >= 1 andalso M < ?Q - 1,
    S = mpz:powm(H, R, ?P),
    C1 = mpz:powm(?G, R, ?P),
    C2 = (M * S) rem ?P,
    {C1, C2}.

%% Exported: decrypt (multiplicative ElGamal decryption)

decrypt({C1, C2}, #sk{x = X}) ->
    S = mpz:powm(C1, X, ?P),
    M = (C2 * mpz:invert(S, ?P)) rem ?P,
    binary:encode_unsigned(M).

%% Exported: modified_encrypt (additive ElGamal encryption)

modified_encrypt(Plaintext, #pk{h = H}) ->
    M = binary:decode_unsigned(Plaintext),
    R = crypto:rand_uniform(1, ?Q),
    C1 = mpz:powm(?G, R, ?P),
    C2 = mpz:powm(?G, M, ?P) * mpz:powm(H, R, ?P) rem ?P,
    {C1, C2}.

%% Exported: modified_decrypt (additive ElGamal decryption)

modified_decrypt(Ciphertext, Sk) ->
    Gm = decrypt(Ciphertext, Sk),
    %% NOTE: I have been experimenting with Pollard’s rho-method to
    %% solve the discrete logarithm but for some reason it is even
    %% *slower* than brute forcing. I must be doing something wrong. :-( 
    %% More info on Pollard's rho-method can be found in
    %% https://www.luke.maurits.id.au/files/misc/honours_thesis.pdf and
    %% https://www.alpertron.com.ar/DILOG.HTM comes helpful during
    %% debugging.
    %% Calling mpz:dlog/3 eventually ends up in dloglib.c but I have a
    %% standlone version, i.e. dlog.c, used for testing from a shell.                                                                     
%%  M = mpz:dlog(binary:decode_unsigned(Gm), ?G, ?P),
    M = brute_force_dlog(binary:decode_unsigned(Gm), 0),
    binary:encode_unsigned(M).

%% NOTE: Brute force only realistically handles plaintexts less than
%% or equal to 24 bits (or else it takes for ever)
brute_force_dlog(Plaintext, N) ->
  case mpz:powm(?G, N, ?P) of
      Plaintext ->
          N;
      _ ->
          brute_force_dlog(Plaintext, N + 1)
  end.

%% Spiridon introduces randomization of ciphertexts using universal
%% re-encryption with a twist, i.e. using both multiplicative and
%% additive Elgamal encryption. Universal re-encryption was introduced 
%% by Golle et al. in "Universal Re-encryption for Mixnets"
%% (https://crypto.stanford.edu/~pgolle/papers/univrenc.pdf).
%%
%% The u* functions below are intended to do encryption as described
%% in Spiridon's paper, i.e. using padding, keyed HMACs, multiplicative
%% and additive ElGamal encryption etc. All this is *not* yet in place
%% but it will be as soon as the discrete logarithms can be solved fast
%% enough. 
%%
%% NOTE: The u* functions operates on list of plaintexts each of
%% MAX_MESSAGE_SIZE. This has a number of obvious benefits.

%% Exported: uencrypt

uencrypt(Plaintexts, Pk) ->
    Ciphertexts =
        lists:map(fun(Plaintext) ->
                          encrypt(Plaintext, Pk)
                  end, Plaintexts),
    {encrypt(<<1>>, Pk), Ciphertexts}.

%% Exported: udecrypt

udecrypt({UnitCiphertext, Ciphertexts}, Sk) ->
    case decrypt(UnitCiphertext, Sk) of
        <<1>> ->
            lists:map(fun(Ciphertext) ->
                              decrypt(Ciphertext, Sk)
                      end, Ciphertexts);
        _ ->
            mismatch
    end.

%% Exported: urandomize

urandomize({{UnitC1, UnitC2}, Ciphertexts}) ->
    K0 = crypto:rand_uniform(1, ?P),
    RandomizedCiphertexts =
        lists:map(fun({C1, C2}) ->
                          K1 = crypto:rand_uniform(1, ?P),
                          {C1 * mpz:powm(UnitC1, K1, ?P),
                           C2 * mpz:powm(UnitC2, K1, ?P)}
                  end, Ciphertexts),
  {{mpz:powm(UnitC1, K0, ?P), mpz:powm(UnitC2, K0, ?P)},
   RandomizedCiphertexts}.
