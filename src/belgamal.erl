-module(belgamal).
-export([encrypt/2, decrypt/2]).
-export([uencrypt/2, udecrypt/2]).
-export([urandomize/1]).
-export([binary_to_public_key/1, binary_to_secret_key/1]).
-export([public_key_to_binary/1, secret_key_to_binary/1]).

-include_lib("apptools/include/shorthand.hrl").
-include("elgamal.hrl").

%% Exported: encrypt

%% NOTE: plaintext can be at most ?MAX_MESSAGE_SIZE bytes
encrypt(Plaintext, Pk) ->
    encode_ciphertext(elgamal:encrypt(Plaintext, Pk)).

%% Exported: decrypt

decrypt(Ciphertext, Sk) ->
    elgamal:decrypt(decode_ciphertext(Ciphertext), Sk).

%% Exported: uencrypt

%% NOTE: plaintext can be of any size
uencrypt(Plaintext, Pk) ->
    {UnitCiphertext, Ciphertexts} =
        elgamal:uencrypt(split_plaintext(Plaintext), Pk),
    encode_ciphertexts([UnitCiphertext|Ciphertexts]).

split_plaintext(Plaintext) ->
    N = ?MAX_MESSAGE_SIZE - 1,
    case Plaintext of
        <<Part:N/binary, Rest/binary>> ->
            [<<1:8, Part/binary>>|split_plaintext(Rest)];
        Part ->
            [<<1:8, Part/binary>>]
    end.

%% Exported: udecrypt

udecrypt(Ciphertext, Sk) ->
    [UnitCiphertext|RemainingCiphertexts] = decode_ciphertexts(Ciphertext),
    case elgamal:udecrypt({UnitCiphertext, RemainingCiphertexts}, Sk) of
        mismatch ->
            mismatch;
        Plaintexts ->
            join_plaintexts(Plaintexts)
    end.

join_plaintexts(Plaintexts) ->
  ?l2b(remove_paddings(Plaintexts)).

remove_paddings(Plaintexts) ->
    case Plaintexts of
        [] ->
            [];
        [<<1:8, Part/binary>>|Rest] ->
            [Part|remove_paddings(Rest)]
    end.

%% Exported: urandomize

urandomize(Ciphertexts) ->
    [UnitCiphertext|RemainingCiphertexts] = decode_ciphertexts(Ciphertexts),
    {RandomizedUnitCiphertext, RandomizedCiphertexts} =
        elgamal:urandomize({UnitCiphertext, RemainingCiphertexts}),
    encode_ciphertexts([RandomizedUnitCiphertext|RandomizedCiphertexts]).

%% Exported: binary_to_public_key

binary_to_public_key(Binary) ->
    #pk{h = binary:decode_unsigned(Binary)}.

%% Exported: binary_to_secret_key

binary_to_secret_key(Binary) ->
    #sk{x = binary:decode_unsigned(Binary)}.

%% Exported: public_key_to_binary

public_key_to_binary(#pk{h = H}) ->
    binary:encode_unsigned(H).

%% Exported: secret_key_to_binary

secret_key_to_binary(#sk{x = X}) ->
    binary:encode_unsigned(X).

%%
%% Utilities
%%

decode_ciphertext(<<C1Size:32, Bc1:C1Size/binary,
                    C2Size:32, Bc2:C2Size/binary>>) ->
    {binary:decode_unsigned(Bc1),
     binary:decode_unsigned(Bc2)}.

decode_ciphertexts(<<>>) ->
    [];
decode_ciphertexts(<<C1Size:32, Bc1:C1Size/binary,
                     C2Size:32, Bc2:C2Size/binary,
                     Rest/binary>>) ->
    [{binary:decode_unsigned(Bc1),
      binary:decode_unsigned(Bc2)}|
     decode_ciphertexts(Rest)].

encode_ciphertext({C1, C2}) ->
    Bc1 = binary:encode_unsigned(C1),
    Bc1Size = size(Bc1),
    Bc2 = binary:encode_unsigned(C2),
    Bc2Size = size(Bc2),
    <<Bc1Size:32, Bc1/binary, Bc2Size:32, Bc2/binary>>.

encode_ciphertexts([]) ->
    <<>>;
encode_ciphertexts([Ciphertext|Rest]) ->
    ?l2b([encode_ciphertext(Ciphertext), encode_ciphertexts(Rest)]).
