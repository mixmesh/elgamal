-module(elgamal).
-export([generate_encryption_factors/1]).
-export([generate_key_pair/0, generate_key_pair/1, generate_key_pair/2]).
-export([encrypt/2, decrypt/2]).
-export([uencrypt/2, udecrypt/2, urandomize/1]).
-export([uencrypt/3]).
-export([uencode/1, udecode/1]).
-export([udecrypt_/2]). %% debug
%% basic universal
-export([sign/2, verify/3]).
-export([info/1]).
-export([binary_to_pk/1, binary_to_sk/1]).
-export([pk_to_binary/1, sk_to_binary/1]).

-include("../include/elgamal.hrl").

%% pair {g^r, m*h^r}
-type ciphpair_t() :: {non_neg_integer(),non_neg_integer()}.

%% -define(dbg(F,A), io:format((F),(A))).
-define(dbg(F,A), ok).
%% This module implements multiplicative *and* additive ElGamal
%% encryption as described in "An Anonymous Messaging System for Delay
%% Tolerant Networks" by Spiridon Bakiras et al. (available locally).
%% Multiplicative ElGamal encryption is also described in general
%% terms in https://en.wikipedia.org/wiki/ElGamal_encryption.

%%
%% Exported: generate_encryption_factors
%%

info(segment_size) -> ?SEGMENT_SIZE;
info(num_segments) -> ?NUM_SEGMENTS;
info(encoded_size) -> ?ENCODED_SIZE;
info(max_message_size) -> ?MAX_MESSAGE_SIZE;
info(max_nym_size) -> ?MAX_NYM_SIZE;
info(p_bit_size) ->
    Bin = binary:encode_unsigned(?P),
    MSB = binary:at(Bin,0),
    trunc(math:log2(MSB))+1+8*(byte_size(Bin)-1).


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

%%
%% Exported: generate_key_pair
%%

-spec generate_key_pair() -> {#pk{}, #sk{}}.

generate_key_pair() ->
    generate_key_pair(<<"default">>).

generate_key_pair(Nym) ->
    X = uniform(1, ?Q),
    generate_key_pair(Nym, X).

generate_key_pair(Nym, X) when is_binary(Nym),
                               byte_size(Nym) =< ?MAX_NYM_SIZE,
                               X < ?Q ->
    H = pow(?G, X, ?P),
    {#pk{nym=Nym, h=H}, #sk{nym=Nym, x=X, h=H}}.

%%
%% Exported: encrypt (multiplicative ElGamal encryption)
%%

-spec encrypt(Plaintext::binary(), #pk{}) -> ciphpair_t().

encrypt(Plaintext, #pk{h = H}) when is_binary(Plaintext) ->
    M = binary:decode_unsigned(Plaintext),
    R = uniform(1, ?Q),
    true = M >= 1 andalso M < ?Q - 1,
    S = pow(H, R, ?P),
    C1 = pow(?G, R, ?P),
    C2 = (M * S) rem ?P,
    {C1, C2}.

%%
%% Exported: decrypt (multiplicative ElGamal decryption)
%%

-spec decrypt(Pair::ciphpair_t(), #sk{}) -> binary().

decrypt({C1, C2}, #sk{x = X}) ->
    S = pow(C1, ?P-1-X, ?P),  %% = C1^-x
    M = (C2 * S) rem ?P,
    binary:encode_unsigned(M).

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
%% MAX_SEGMENT_SIZE. This has a number of obvious benefits.

%%
%% Exported: uencrypt
%%

-spec uencrypt(Plaintext::binary(),
	       ReceiverPk::#pk{}, SenderSk::#sk{}) ->
	  binary().

uencrypt(Plaintext, ReceiverPk, SenderSk=#sk{nym=Nym}) when
      is_binary(Plaintext),
      byte_size(Plaintext) =< ?MAX_MESSAGE_SIZE ->
    TextLen = byte_size(Plaintext),
    NymLen  = byte_size(Nym),
    NymPad  = random_bytes(?MAX_NYM_SIZE-NymLen),
    NymBin  = <<Nym/binary,NymPad/binary>>,
    Sign = sign(Plaintext, SenderSk),
    SignBin = zencode(Sign,?ENCODED_SEGMENT_SIZE),
    PadLen = ?MAX_MESSAGE_SIZE - TextLen,
    Pad = random_bytes(PadLen),
    Bin = <<TextLen:32,                  %% 4
	    NymLen:8, NymBin/binary,     %% ?BIN_NYM_SIZE (32)
	    SignBin/binary,
	    Plaintext/binary,
	    Pad/binary>>,
    ?dbg("encrypt: bin size = ~w\n", [byte_size(Bin)]),
    Parts = [P || <<P:?SEGMENT_SIZE/binary>> <= Bin],
    ?dbg("encrypt: nparts=~w, sizes=~w\n",
	 [length(Parts),[byte_size(Pi) || Pi <- Parts]]),
    uencode(uencrypt(Parts, ReceiverPk)).

uencrypt(Parts, Pk) ->
    {encrypt(<<1>>, Pk), [encrypt(Pi, Pk) || Pi <- Parts]}.

%%
%% Exported: udecrypt
%%

%% if udecrypt is successful then call verify
%% with signature and public key of Nym.

-spec udecrypt(Chipher::binary(), ReceiverSk::#sk{}) ->
	  mismatch |
	  error |
	  {Nym::binary(),Signature::non_neg_integer(),Message::binary()}.

udecrypt(Data, Sk) when is_binary(Data) ->
    Chipher = {_C1,_Cs} = udecode(Data),
    case udecrypt_(Chipher, Sk) of
	mismatch ->
	    mismatch;
	Parts0 ->
	    %% prepend zeros if size is to small
	    Parts = [zprep(Pi,?SEGMENT_SIZE) || Pi <- Parts0],
	    ?dbg("udecrypt: nparts=~w, sizes=~w\n",
		 [length(Parts), [byte_size(Pi) || Pi <- Parts]]),
	    Bin = iolist_to_binary(Parts),
	    ?dbg("decrypt: text size = ~w\n", [byte_size(Bin)]),
	    case Bin of
		<<LenText:32,
		  NymLen:8, Nym:NymLen/binary, _:(?MAX_NYM_SIZE-NymLen)/binary,
		  SignBin:?ENCODED_SEGMENT_SIZE/binary,
		  PlainText:LenText/binary,
		  _/binary>> ->
		    {Nym,binary:decode_unsigned(SignBin),PlainText};
		_ ->
		    error
	    end
    end;
udecrypt(Cipher={_C1,_Cs}, Sk) ->
    udecrypt_(Cipher, Sk).

udecrypt_(_Cipher={C1, Cs}, Sk) ->
    case decrypt(C1, Sk) of
        <<1>> ->
	    [decrypt(Ci, Sk) || Ci <-  Cs];
        _ ->
            mismatch
    end.

%% prepend zeros as needed
zprep(Bin, Size) when byte_size(Bin) < Size ->
    <<0:(Size-byte_size(Bin))/unit:8, Bin/binary>>;
zprep(Bin, _Size) -> Bin.

%%
%% Exported: urandomize
%%

urandomize(Data) when is_binary(Data) ->
    Cipher ={_C1,_Cs} = udecode(Data),
    uencode(urandomize_(Cipher));
urandomize(Cipher={_C1,_Cs}) ->
    urandomize_(Cipher).

urandomize_({{UnitC1, UnitC2}, Ciphertexts}) ->
    K0 = uniform(1, ?P),
    RandomizedCiphertexts =
        lists:map(fun({C1, C2}) ->
                          K1 = uniform(1, ?P),
                          {(C1 * pow(UnitC1, K1, ?P)) rem ?P,
                           (C2 * pow(UnitC2, K1, ?P)) rem ?P}
                  end, Ciphertexts),
    {{pow(UnitC1, K0, ?P), pow(UnitC2, K0, ?P)},
     RandomizedCiphertexts}.

%%
%% Encode cipher pair sequence into a binary
%%
-spec uencode({ciphpair_t(),[ciphpair_t()]}) ->
	  binary().

uencode({C1, Cs}) ->
    iolist_to_binary([uencode_pair(C1) | [uencode_pair(Ci) || Ci <- Cs]]).

uencode_pair({C1,C2}) ->
    <<(zencode(C1, ?ENCODED_SEGMENT_SIZE))/binary,
      (zencode(C2, ?ENCODED_SEGMENT_SIZE))/binary>>.

zencode(Int, Len) when is_integer(Int), Int > 0 ->
    Bin = binary:encode_unsigned(Int),
    Pad = Len - byte_size(Bin),
    <<0:Pad/unit:8, Bin/binary>>.

%%
%% Decode a binary into cipher pair sequence
%%
-spec udecode(binary()) ->
	  {ciphpair_t(),[ciphpair_t()]}.

udecode(Data) ->
    [C1|Cs] =
	[{binary:decode_unsigned(B1),
	  binary:decode_unsigned(B2)} ||
	    <<B1:?ENCODED_SEGMENT_SIZE/binary,
	      B2:?ENCODED_SEGMENT_SIZE/binary>> <= Data],
    {C1, Cs}.

-define(HMACHASH, sha256).
%%
%% sign a message example signature = (G^m)^x
%%  m = H(h | message)
%%
-spec sign(Message::binary(), #sk{}) ->
	  non_neg_integer().

sign(Message, #sk{x=X,h=H}) ->
    Mac = crypto:mac(hmac, ?HMACHASH, binary:encode_unsigned(H), Message),
    M = binary:decode_unsigned(Mac),
    pow(pow(?G,M,?P),X,?P).

%% Given signature message and the public key check that message match
%%  m = H(h | message)
%%  h'^m * signature = (g^-x)^m * signature = g^-xm * g^xm = 1
%%

-spec verify(Signature::non_neg_integer(),Message::binary(), #pk{}) ->
	  boolean().

verify(Signature, Message, #pk{h=H}) ->
    Mac = crypto:mac(hmac, ?HMACHASH, binary:encode_unsigned(H), Message),
    M = binary:decode_unsigned(Mac),
    Verifier = pow(inv(H,?P),M,?P),
    case (Verifier*Signature) rem ?P of
	1 -> true;
	_ -> false
    end.

uniform(Min, Max) ->
    Min1 = Min - 1,
    N = Max-Min1,
    R = rand:uniform(N),
    R+Min1.

random_bytes(N) ->
    list_to_binary([(rand:uniform(256)-1) || _ <- lists:seq(1,N)]).

pow(A, B, P) ->
    binary:decode_unsigned(crypto:mod_pow(A, B, P)).

inv(A, P) ->
    mpz:invert(A, P).

%%
%% Exported: binary_to_pk
%%

binary_to_pk(<<NymSize:8/unsigned-integer, Nym:NymSize/binary, HBin/binary>>) ->
    #pk{nym = Nym, h = binary:decode_unsigned(HBin)}.

%%
%% Exported: binary_to_sk
%%

binary_to_sk(<<NymSize:8/unsigned-integer, Nym:NymSize/binary,
               XBinSize:8/unsigned-integer, XBin:XBinSize/binary,
               HBin/binary>>) ->
    #sk{nym = Nym,
        x = binary:decode_unsigned(XBin),
        h = binary:decode_unsigned(HBin)}.

%%
%% Exported: binary_to_pk
%%

pk_to_binary(#pk{nym = Nym, h = H}) ->
    NymSize = size(Nym),
    HBin = binary:encode_unsigned(H),
    <<NymSize:8/unsigned-integer, Nym/binary,
      HBin/binary>>.

%%
%% Exported: sk_to_binary
%%

sk_to_binary(#sk{nym = Nym, x = X, h = H}) ->
    NymSize = size(Nym),
    XBin = binary:encode_unsigned(X),
    XBinSize = size(XBin),
    HBin = binary:encode_unsigned(H),
    <<NymSize:8/unsigned-integer, Nym/binary,
      XBinSize:8/unsigned-integer, XBin/binary,
      HBin/binary>>.
