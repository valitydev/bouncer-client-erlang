-module(bouncer_client_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-include_lib("bouncer_proto/include/bouncer_decision_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_base_thrift.hrl").

-export([all/0]).

-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([empty_judge/1]).
-export([follows_retries/1]).
-export([follows_timeout/1]).
-export([validate_user_fragment/1]).
-export([validate_env_fragment/1]).
-export([validate_auth_fragment/1]).
-export([validate_auth_fragment_scope/1]).
-export([validate_requester_fragment/1]).
-export([validate_complex_fragment/1]).
-export([validate_remote_user_fragment/1]).

-type test_case_name() :: atom().

-define(RULESET_ID, <<"service/authz/api">>).

%% tests descriptions

-spec all() -> [{atom(), test_case_name()} | test_case_name()].
all() ->
    [
        {group, default}
    ].

-spec groups() -> [{atom(), list(), [test_case_name()]}].
groups() ->
    [
        {default, [], [
            empty_judge,
            follows_retries,
            follows_timeout,
            validate_user_fragment,
            validate_env_fragment,
            validate_auth_fragment,
            validate_auth_fragment_scope,
            validate_requester_fragment,
            validate_complex_fragment,
            validate_remote_user_fragment
        ]}
    ].

-type config() :: [{atom(), any()}].

-define(TIMEOUT, 1000).
-define(RETRY_NUM, 3).
-define(RETRY_TIMEOUT, 100).
-define(RETRY_STRATEGY, {linear, ?RETRY_NUM, ?RETRY_TIMEOUT}).

-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    Apps =
        genlib_app:start_application_with(bouncer_client, [
            {service_clients, #{
                bouncer => #{
                    url => <<"http://bouncer:8022/">>,
                    timeout => ?TIMEOUT,
                    retries => #{
                        'Judge' => ?RETRY_STRATEGY,
                        '_' => finish
                    }
                },
                org_management => #{
                    url => <<"http://org_management:8022/">>,
                    retries => #{
                        % function => retry strategy
                        % '_' work as "any"
                        % default value is 'finish'
                        % for more info look genlib_retry :: strategy()
                        % https://github.com/rbkmoney/genlib/blob/master/src/genlib_retry.erl#L19
                        'GetUserContext' => {linear, 3, 100},
                        '_' => finish
                    }
                }
            }}
        ]),
    [{apps, Apps}] ++ Config.

-spec end_per_suite(config()) -> _.
end_per_suite(Config) ->
    _ = [application:stop(App) || App <- proplists:get_value(apps, Config)],
    Config.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(_Name, C) ->
    [{test_sup, start_mocked_service_sup()} | C].

-spec end_per_testcase(test_case_name(), config()) -> ok.
end_per_testcase(_Name, C) ->
    stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%

-spec empty_judge(config()) -> _.
empty_judge(C) ->
    _ = mock_services(
        [
            {bouncer, fun('Judge', _) ->
                {ok, #decision_Judgement{
                    resolution = {allowed, #decision_ResolutionAllowed{}}
                }}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(?RULESET_ID, #{}, WoodyContext).

-spec follows_retries(config()) -> _.
follows_retries(_C) ->
    WoodyContext = woody_context:new(),
    T0 = erlang:monotonic_time(millisecond),
    ?assertError(
        {woody_error, {internal, resource_unavailable, _}},
        bouncer_client:judge(?RULESET_ID, #{}, WoodyContext)
    ),
    T1 = erlang:monotonic_time(millisecond),
    ?assert(T1 - T0 > ?RETRY_NUM * ?RETRY_TIMEOUT),
    ?assert(T1 - T0 < ?RETRY_NUM * ?RETRY_TIMEOUT * 1.5).

-spec follows_timeout(config()) -> _.
follows_timeout(C) ->
    _ = mock_services(
        [
            {bouncer, fun('Judge', _) ->
                ok = timer:sleep(5000),
                {ok, #decision_Judgement{
                    resolution = {allowed, #decision_ResolutionAllowed{}}
                }}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    T0 = erlang:monotonic_time(millisecond),
    ?assertError(
        {woody_error, {external, result_unknown, _}},
        bouncer_client:judge(?RULESET_ID, #{}, WoodyContext)
    ),
    T1 = erlang:monotonic_time(millisecond),
    ?assert(T1 - T0 > ?TIMEOUT),
    ?assert(T1 - T0 < ?TIMEOUT * 1.5).

-spec validate_user_fragment(config()) -> _.
validate_user_fragment(C) ->
    UserID = <<"somebody">>,
    UserRealm = <<"once">>,
    OrgID = <<"told">>,
    PartyID = <<"me">>,
    _ = mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                Auth = get_fragment(<<"user">>, Fragments),
                ?assertEqual(
                    #ctx_v1_ContextFragment{
                        user = #ctx_v1_User{
                            id = UserID,
                            realm = #base_Entity{id = UserRealm},
                            orgs = [
                                #ctx_v1_Organization{
                                    id = OrgID,
                                    party = #base_Entity{id = PartyID},
                                    owner = #base_Entity{id = UserID}
                                }
                            ]
                        }
                    },
                    Auth
                ),
                {ok, #decision_Judgement{
                    resolution = {allowed, #decision_ResolutionAllowed{}}
                }}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{
            fragments => #{
                <<"user">> => bouncer_context_helpers:make_user_fragment(#{
                    id => UserID,
                    realm => #{id => UserRealm},
                    orgs => [#{id => OrgID, party => #{id => PartyID}, owner => #{id => UserID}}]
                })
            }
        },
        WoodyContext
    ).

-spec validate_env_fragment(config()) -> _.
validate_env_fragment(C) ->
    Time = genlib_rfc3339:format(genlib_time:unow(), second),
    _ = mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_time(Fragments) of
                    Time ->
                        {ok, #decision_Judgement{
                            resolution = {allowed, #decision_ResolutionAllowed{}}
                        }};
                    _ ->
                        {ok, #decision_Judgement{
                            resolution = {forbidden, #decision_ResolutionForbidden{}}
                        }}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"env">> => bouncer_context_helpers:make_env_fragment(#{now => Time})}},
        WoodyContext
    ).

-spec validate_auth_fragment(config()) -> _.
validate_auth_fragment(C) ->
    Method = <<"someMethod">>,
    TokenID = <<"📟"/utf8>>,
    TokenAccess = [
        #{
            id => <<"some-api">>,
            roles => [<<"do-nothing">>]
        }
    ],
    _ = mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                Auth = get_fragment(<<"auth">>, Fragments),
                ?assertEqual(
                    #ctx_v1_ContextFragment{
                        auth = #ctx_v1_Auth{
                            method = Method,
                            token = #ctx_v1_Token{
                                id = TokenID,
                                access = [
                                    #ctx_v1_ResourceAccess{
                                        id = <<"some-api">>,
                                        roles = [<<"do-nothing">>]
                                    }
                                ]
                            }
                        }
                    },
                    Auth
                ),
                {ok, #decision_Judgement{
                    resolution = {allowed, #decision_ResolutionAllowed{}}
                }}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{
            fragments => #{
                <<"auth">> => bouncer_context_helpers:make_auth_fragment(#{
                    method => Method,
                    token => #{
                        id => TokenID,
                        access => TokenAccess
                    }
                })
            }
        },
        WoodyContext
    ).

-spec validate_auth_fragment_scope(config()) -> _.
validate_auth_fragment_scope(C) ->
    Method = <<"Blep">>,
    PartyID = <<"PARTY">>,
    CustomerID = <<"🎎"/utf8>>,
    InvoiceTemplateID = <<"🎷"/utf8>>,
    _ = mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                Auth = get_fragment(<<"auth">>, Fragments),
                ?assertEqual(
                    #ctx_v1_ContextFragment{
                        auth = #ctx_v1_Auth{
                            method = Method,
                            scope = [
                                #ctx_v1_AuthScope{
                                    invoice_template = #base_Entity{id = InvoiceTemplateID},
                                    customer = #base_Entity{id = CustomerID}
                                },
                                #ctx_v1_AuthScope{party = #base_Entity{id = PartyID}}
                            ]
                        }
                    },
                    Auth
                ),
                {ok, #decision_Judgement{
                    resolution = {allowed, #decision_ResolutionAllowed{}}
                }}
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{
            fragments => #{
                <<"auth">> => bouncer_context_helpers:make_auth_fragment(#{
                    method => Method,
                    scope => [
                        #{party => #{id => PartyID}},
                        #{
                            customer => #{id => CustomerID},
                            invoice_template => #{id => InvoiceTemplateID}
                        }
                    ]
                })
            }
        },
        WoodyContext
    ).

-spec validate_requester_fragment(config()) -> _.
validate_requester_fragment(C) ->
    IP = "someIP",
    _ = mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_ip(Fragments) of
                    undefined ->
                        {ok, #decision_Judgement{
                            resolution = {forbidden, #decision_ResolutionForbidden{}}
                        }};
                    BinaryIP ->
                        case binary_to_list(BinaryIP) of
                            IP ->
                                {ok, #decision_Judgement{
                                    resolution = {allowed, #decision_ResolutionAllowed{}}
                                }};
                            _ ->
                                {ok, #decision_Judgement{
                                    resolution = {forbidden, #decision_ResolutionForbidden{}}
                                }}
                        end
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"requester">> => bouncer_context_helpers:make_requester_fragment(#{ip => IP})}},
        WoodyContext
    ).

-spec validate_complex_fragment(config()) -> _.
validate_complex_fragment(C) ->
    _ = mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case Fragments of
                    #decision_Context{fragments = #{<<"complex">> := Fragment}} ->
                        case decode_fragment(Fragment) of
                            #ctx_v1_ContextFragment{
                                env = #ctx_v1_Environment{},
                                auth = #ctx_v1_Auth{},
                                user = #ctx_v1_User{}
                            } ->
                                {ok, #decision_Judgement{
                                    resolution = {allowed, #decision_ResolutionAllowed{}}
                                }};
                            _ ->
                                {ok, #decision_Judgement{
                                    resolution = {forbidden, #decision_ResolutionForbidden{}}
                                }}
                        end;
                    _ ->
                        {ok, #decision_Judgement{
                            resolution = {forbidden, #decision_ResolutionForbidden{}}
                        }}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    ComplexFragment =
        bouncer_context_helpers:add_user(
            #{
                id => <<"USER">>,
                realm => #{id => <<"external">>},
                email => <<"user@example.org">>,
                orgs => [
                    #{
                        id => <<"ORG">>,
                        roles => [
                            #{id => <<"COMMANDER">>, scope => #{shop => #{id => <<"SHOP">>}}}
                        ]
                    }
                ]
            },
            bouncer_context_helpers:add_auth(
                #{method => <<"METHOD">>},
                bouncer_context_helpers:make_env_fragment(
                    #{now => genlib_rfc3339:format(genlib_time:unow(), second)}
                )
            )
        ),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"complex">> => ComplexFragment}},
        WoodyContext
    ).

-spec validate_remote_user_fragment(config()) -> _.
validate_remote_user_fragment(C) ->
    UserID = <<"someUser">>,
    _ = mock_services(
        [
            {org_management, fun('GetUserContext', _) ->
                Content = encode(#ctx_v1_ContextFragment{
                    user = #ctx_v1_User{
                        id = UserID
                    }
                }),
                {ok, #ctx_ContextFragment{type = v1_thrift_binary, content = Content}}
            end},
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_user_id(Fragments) of
                    UserID ->
                        {ok, #decision_Judgement{
                            resolution = {allowed, #decision_ResolutionAllowed{}}
                        }};
                    _ ->
                        {ok, #decision_Judgement{
                            resolution = {forbidden, #decision_ResolutionForbidden{}}
                        }}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    {ok, EncodedUserFragment} = bouncer_context_helpers:get_user_orgs_fragment(UserID, WoodyContext),
    allowed = bouncer_client:judge(?RULESET_ID, #{fragments => #{<<"user">> => EncodedUserFragment}}, WoodyContext).

%%

get_ip(#decision_Context{
    fragments = #{<<"requester">> := Fragment}
}) ->
    #ctx_v1_ContextFragment{requester = #ctx_v1_Requester{ip = IP}} = decode_fragment(Fragment),
    IP.

get_time(#decision_Context{
    fragments = #{<<"env">> := Fragment}
}) ->
    #ctx_v1_ContextFragment{env = #ctx_v1_Environment{now = Time}} = decode_fragment(Fragment),
    Time.

get_user_id(#decision_Context{
    fragments = #{<<"user">> := Fragment}
}) ->
    #ctx_v1_ContextFragment{user = #ctx_v1_User{id = UserID}} = decode_fragment(Fragment),
    UserID.

get_fragment(ID, #decision_Context{fragments = Fragments}) ->
    decode_fragment(maps:get(ID, Fragments)).

decode_fragment(#ctx_ContextFragment{type = v1_thrift_binary, content = Content}) ->
    case decode_fragment_content(Content) of
        Fragment = #ctx_v1_ContextFragment{} ->
            Fragment;
        {error, Reason} ->
            error(Reason)
    end.

decode_fragment_content(Content) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    case thrift_strict_binary_codec:read(Codec, Type) of
        {ok, CtxThrift, Codec1} ->
            case thrift_strict_binary_codec:close(Codec1) of
                <<>> ->
                    CtxThrift;
                Leftovers ->
                    {error, {excess_binary_data, Leftovers}}
            end;
        Error ->
            Error
    end.

encode(ContextFragment) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

%%

start_mocked_service_sup() ->
    {ok, SupPid} = genlib_adhoc_supervisor:start_link(#{}, []),
    _ = unlink(SupPid),
    SupPid.

-spec stop_mocked_service_sup(pid()) -> _.
stop_mocked_service_sup(SupPid) ->
    exit(SupPid, shutdown).

-define(APP, bouncer_client).
-define(HOST_IP, "::").
-define(HOST_NAME, "localhost").

mock_services(Services, SupOrConfig) ->
    maps:map(fun set_cfg/2, mock_services_(Services, SupOrConfig)).

set_cfg(Service, Url) ->
    {ok, Clients} = application:get_env(?APP, service_clients),
    #{Service := BouncerCfg} = Clients,
    ok = application:set_env(
        ?APP,
        service_clients,
        Clients#{Service => BouncerCfg#{url => Url}}
    ).

mock_services_(Services, Config) when is_list(Config) ->
    mock_services_(Services, ?config(test_sup, Config));
mock_services_(Services, SupPid) when is_pid(SupPid) ->
    ServerRef = {dummy, lists:map(fun get_service_name/1, Services)},
    {ok, IP} = inet:parse_address(?HOST_IP),
    ChildSpec = woody_server:child_spec(
        ServerRef,
        Options = #{
            ip => IP,
            port => 0,
            event_handler => scoper_woody_event_handler,
            handlers => lists:map(fun mock_service_handler/1, Services)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),
    {IP, Port} = woody_server:get_addr(ServerRef, Options),
    lists:foldl(
        fun(Service, Acc) ->
            ServiceName = get_service_name(Service),
            Acc#{ServiceName => make_url(ServiceName, Port)}
        end,
        #{},
        Services
    ).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {bouncer_client_mock_service, #{function => Fun}}}}.

get_service_modname(org_management) ->
    {orgmgmt_authctx_provider_thrift, 'AuthContextProvider'};
get_service_modname(bouncer) ->
    {bouncer_decision_thrift, 'Arbiter'}.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).
