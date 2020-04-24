%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqtt_sasl).

-include("emqx_sasl.hrl").

-export([ add/3
        , check/3
        , make_client_first/1
        , supported/0 ]).

add(Username, Password, Salt) ->
    emqx_sasl_scram:add(Username, Password, Salt).

check(<<"SCRAM-SHA-1">>, Data, Cache) ->
    case maps:get(client_final, Cache, undefined) of
        undefined -> check_server_first(Data, Cache);
        _ -> check_server_final(Data, Cache)
    end;

check(_, _, _) ->
    {error, unsupported_mechanism}.

check_server_first(ServerFirst, #{password := Password, client_first := ClientFirst}) ->
    Attributes = emqx_sasl_scram:parse(ServerFirst),
    Nonce = proplists:get_value(nonce, Attributes),
    ClientFirstWithoutHeader = emqx_sasl_scram:without_header(ClientFirst),
    ClientFinalWithoutProof = emqx_sasl_scram:serialize([{channel_binding, <<"biws">>}, {nonce, Nonce}]),
    Auth = list_to_binary(io_lib:format("~s,~s,~s", [ClientFirstWithoutHeader, ServerFirst, ClientFinalWithoutProof])),
    Salt = base64:decode(proplists:get_value(salt, Attributes)),
    IterationCount = binary_to_integer(proplists:get_value(iteration_count, Attributes)),
    SaltedPassword = emqx_sasl_scram:pbkdf2_sha_1(Password, Salt, IterationCount),
    ClientKey = emqx_sasl_scram:client_key(SaltedPassword),
    StoredKey = crypto:hash(sha, ClientKey),
    ClientSignature = emqx_sasl_scram:hmac(StoredKey, Auth),
    ClientProof = base64:encode(crypto:exor(ClientKey, ClientSignature)),
    ClientFinal = emqx_sasl_scram:serialize([{channel_binding, <<"biws">>},
                                             {nonce, Nonce},
                                             {proof, ClientProof}]),
    {continue, ClientFinal, #{password => Password,
                              client_first => ClientFirst,
                              server_first => ServerFirst,
                              client_final => ClientFinal}}.

check_server_final(ServerFinal, #{password := Password,
                                  client_first := ClientFirst,
                                  server_first := ServerFirst,
                                  client_final := _ClientFinal
                                  }) ->
    NewAttributes = emqx_sasl_scram:parse(ServerFinal),
    Attributes = emqx_sasl_scram:parse(ServerFirst),
    Nonce = proplists:get_value(nonce, Attributes),
    ClientFirstWithoutHeader = emqx_sasl_scram:without_header(ClientFirst),
    ClientFinalWithoutProof = emqx_sasl_scram:serialize([{channel_binding, <<"biws">>}, {nonce, Nonce}]),
    Auth = list_to_binary(io_lib:format("~s,~s,~s", [ClientFirstWithoutHeader, ServerFirst, ClientFinalWithoutProof])),
    Salt = base64:decode(proplists:get_value(salt, Attributes)),
    IterationCount = binary_to_integer(proplists:get_value(iteration_count, Attributes)),
    SaltedPassword = emqx_sasl_scram:pbkdf2_sha_1(Password, Salt, IterationCount),
    ServerKey = emqx_sasl_scram:server_key(SaltedPassword),
    ServerSignature = emqx_sasl_scram:hmac(ServerKey, Auth),
    base64:encode(ServerSignature) =:= proplists:get_value(verifier, NewAttributes).

make_client_first(Username) ->
    list_to_binary("n,," ++ binary_to_list(emqx_sasl_scram:serialize([{username, Username}, {nonce, emqx_sasl_scram:nonce()}]))).

supported() ->
    [<<"SCRAM-SHA-1">>].
