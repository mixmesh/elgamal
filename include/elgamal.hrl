-ifndef(ELGAMAL_HRL).
-define(ELGAMAL_HRL, true).

-define(MAX_NYM_SIZE, 31).

%% Public key
-record(pk, {
	     nym :: binary(),         %% len <= ?MAX_NUM_SIZE
             h :: non_neg_integer()   %% g^x (mod P)
            }).

%% Secret key (also keep public key here, to avoid calculation)
-record(sk, {
	     nym :: binary(),         %% len <= ?MAX_NUM_SIZE
             x :: non_neg_integer(),  %% 1..Q
             h :: non_neg_integer()   %% g^x (mod P)
            }).

%% The ElGamal encryption depends on non-hidden ElGamal constants in
%% order to make randomization of ciphertexts feasible (see below).
%% This might be a problem as described in section 6.2 in
%% https://hal.inria.fr/hal-01376934v2/document. The current constants
%% are carefully picked but longer safe primes can be generated with
%% elgamal:generate_encryption_factors/0.

-define(P_OLD, ((1 bsl 1024) - 1093337)).
-define(G_OLD, 7).

-define(P_512, 8056937621219442335800311425201562898257642378144104229753985978661308418399777600659774378540097541645283076483268774742323432328119458681350996815299627).
-define(G_512, 7).

-define(P_1024, 1191703890297837857254846218124820162520314254482239260141586246493315566589245659462156276340012962327654624865776671922725912417154643528357403702766406672783187741039499777500937664819366321506835371609274218842538110523885904400885445461904752292635899168049169243216400297218378136654191604761801220538347).
-define(G_1024, 7).

%% The largest 1024-bit safe prime
-define(P, ?P_1024).
%% Base point for modular exponentiation
-define(G, ?G_1024).
%% Order of group generated by p and equals p-1
-define(Q, ((?P - 1) div 2)).
%% The largest possible plaintext message
-define(SEGMENT_SIZE, 128).          %% plain text size
-define(ENCODED_SEGMENT_SIZE, 129).  %% P need more than 1024 bits
-define(NUM_SEGMENTS, 10).           %% segments to send in one message
%% first segment is <<1>>
-define(PAYLOAD_SIZE, (9*?SEGMENT_SIZE)).
-define(ENCODED_SIZE, (10*2*?ENCODED_SEGMENT_SIZE)).
-define(BIN_NYM_SIZE, 32).  %% include length (random pad)
-define(MAX_MESSAGE_SIZE, (?PAYLOAD_SIZE-(4+?BIN_NYM_SIZE+?ENCODED_SEGMENT_SIZE))).

-endif.
