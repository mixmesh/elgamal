-module(elgamal).
-export([generate_encryption_factors/1]).
-export([generate_key_pair/0]).
-export([encrypt/2, decrypt/2]).
-export([modified_encrypt/2, modified_decrypt/2]).
-export([uencrypt/2, udecrypt/2, urandomize/1]).
%% basic universal 
-export([uencrypt0/2, udecrypt0/2, ureencrypt0/1]).

-include("../include/elgamal.hrl").

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

%%
%% For each prime factor x of p−1, verify that g^((p−1)/x) != 1 (mod p)
%% for safe prime then x = 2 and q
%% 
new_generator(Q, P) ->
    G = uniform(1, P),
    case pow(G, Q, P) =/= 1 andalso pow(G, 2, P) =/= 1 of
        true ->
            G;
        false ->
            new_generator(Q, P)
    end.

%% Exported: generate_key_pair

generate_key_pair() ->
    X = uniform(1, ?Q),
    H = pow(?G, X, ?P),
    {#pk{h = H}, #sk{x = X}}.

%% Exported: encrypt (multiplicative ElGamal encryption)

encrypt(Plaintext, #pk{h = H}) when is_binary(Plaintext) ->
    M = binary:decode_unsigned(Plaintext),
    R = uniform(1, ?Q),
    true = M >= 1 andalso M < ?Q - 1,
    S = pow(H, R, ?P),
    C1 = pow(?G, R, ?P),
    C2 = (M * S) rem ?P,
    {C1, C2}.

%% Exported: decrypt (multiplicative ElGamal decryption)

decrypt({C1, C2}, #sk{x = X}) ->
    S = pow(C1, ?P-1-X, ?P),  %% = C1^-x
    M = (C2 * S) rem ?P,
    binary:encode_unsigned(M).

%% Exported: modified_encrypt (additive ElGamal encryption)

modified_encrypt(Plaintext, #pk{h = H}) ->
    M = binary:decode_unsigned(Plaintext),
    R = uniform(1, ?Q),
    C1 = pow(?G, R, ?P),
    C2 = (pow(?G, M, ?P) * pow(H, R, ?P)) rem ?P,
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
  case pow(?G, N, ?P) of
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
    K0 = uniform(1, ?P),
    RandomizedCiphertexts =
        lists:map(fun({C1, C2}) ->
                          K1 = uniform(1, ?P),
                          {C1 * pow(UnitC1, K1, ?P),
                           C2 * pow(UnitC2, K1, ?P)}
                  end, Ciphertexts),
    {{pow(UnitC1, K0, ?P), pow(UnitC2, K0, ?P)},
     RandomizedCiphertexts}.


%% (basic) universal encrypt
uencrypt0(PlainText, Pk) ->
    Bin = erlang:iolist_to_binary(PlainText),
    M = binary:decode_unsigned(Bin),
    true = M >= 1 andalso M < ?Q-1,
    uencrypt0_(M, Pk).

uencrypt0_(M, #pk{h=H}) ->
    K0 = uniform(1, ?Q-2),
    K1 = uniform(1, ?Q-2),
    A0 = (M*pow(H,K0,?P)) rem ?P,
    B0 = pow(?G,K0,?P),
    A1 = pow(H,K1,?P),
    B1 = pow(?G,K1,?P),
    {{A0,B0},{A1,B1}}.

udecrypt0(Cipher, Sk) ->
    case udecrypt0_(Cipher, Sk) of
	false -> false;
	M -> binary:encode_unsigned(M)
    end.

udecrypt0_({{A0,B0},{A1,B1}}, #sk{x=X}) ->
    case A1*pow(B1,?P-1-X,?P) rem ?P of
	1 -> A0*pow(B0,?P-1-X,?P) rem ?P;
	_ -> false
    end.

ureencrypt0({{A0,B0},{A1,B1}}) ->
    K0 = uniform(1, ?Q-2),
    K1 = uniform(1, ?Q-2),
    A0_1 = (A0*pow(A1,K0,?P)) rem ?P,
    B0_1 = (B0*pow(B1,K0,?P)) rem ?P,
    A1_1 = pow(A1,K1,?P),
    B1_1 = pow(B1,K1,?P),
    {{A0_1,B0_1},{A1_1,B1_1}}.

uniform(Min, Max) ->
    Min1 = Min - 1,
    N = Max-Min1,
    R = rand:uniform(N),
    R+Min1.

pow(A, B, M) ->
    binary:decode_unsigned(crypto:mod_pow(A, B, M)).
