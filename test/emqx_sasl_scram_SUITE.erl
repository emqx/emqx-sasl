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

-module(emqx_sasl_scram_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

init_per_suite(Config) ->
    emqx_ct_helpers:start_apps([emqx_sasl]),
    Config.

end_per_suite(_Config) ->
    emqx_ct_helpers:stop_apps([]).

all() -> emqx_ct:all(?MODULE).

t_crud(_) ->
    Username = <<"test">>,
    Password = <<"public">>,
    Salt = <<"emqx">>,
    IterationCount = 4096,
    EncodedSalt = base64:encode(Salt),
    SaltedPassword = emqx_sasl_scram:pbkdf2_sha_1(Password, Salt, IterationCount),
    ClientKey = emqx_sasl_scram:client_key(SaltedPassword),
    ServerKey = base64:encode(emqx_sasl_scram:server_key(SaltedPassword)),
    StoredKey = base64:encode(crypto:hash(sha, ClientKey)),

    {error, not_found} = emqx_sasl_scram:lookup(Username),
    ok = emqx_sasl_scram:add(Username, Password, Salt),
    {error, already_existed} = emqx_sasl_scram:add(Username, Password, Salt),

    {ok, #{username := Username,
           stored_key := StoredKey,
           server_key := ServerKey,
           salt := EncodedSalt,
           iteration_count := IterationCount}} = emqx_sasl_scram:lookup(Username),

    NewSalt = <<"new salt">>,
    NewEncodedSalt = base64:encode(NewSalt),
    emqx_sasl_scram:update(Username, Password, NewSalt),
    {ok, #{username := Username,
           salt := NewEncodedSalt}} = emqx_sasl_scram:lookup(Username),
    emqx_sasl_scram:delete(Username),
    {error, not_found} = emqx_sasl_scram:lookup(Username).

t_scram(_) ->
    Username = <<"test">>,
    Password = <<"public">>,
    ok = emqx_sasl_scram:add(Username, Password, <<"emqx">>),
    ClientFirst = make_client_first(Username),
    io:format("ClientFirst: ~p~n", [ClientFirst]),
    {continue, ServerFirst, Cache} = emqx_sasl_scram:check(ClientFirst, #{}),
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
    {ok, ServerFinal} = emqx_sasl_scram:check(ClientFinal, Cache),
    NewAttributes = emqx_sasl_scram:parse(ServerFinal),
    ServerKey = emqx_sasl_scram:server_key(SaltedPassword),
    ServerSignature = emqx_sasl_scram:hmac(ServerKey, Auth),
    ?assertEqual(base64:encode(ServerSignature), proplists:get_value(verifier, NewAttributes)).

make_client_first(Username) ->
    list_to_binary("n,," ++ binary_to_list(emqx_sasl_scram:serialize([{username, Username}, {nonce, emqx_sasl_scram:nonce()}]))).
