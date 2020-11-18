-module(bouncer_client_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-export([all/0]).

-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([empty_judge/1]).
-export([validate_default_user_fragment/1]).
-export([validate_user_fragment/1]).
-export([validate_env_fragment/1]).
-export([validate_auth_fragment/1]).
-export([validate_requester_fragment/1]).
-export([validate_remote_user_fragment/1]).

-type test_case_name() :: atom().

-define(RULESET_ID, <<"service/authz/api">>).

%% tests descriptions

-spec all() -> [test_case_name()].
all() ->
    [
        {group, default}
    ].

-spec groups() -> [{atom(), list(), [test_case_name()]}].
groups() ->
    [
        {default, [], [
            empty_judge,
            validate_default_user_fragment,
            validate_user_fragment,
            validate_env_fragment,
            validate_auth_fragment,
            validate_requester_fragment,
            validate_remote_user_fragment
        ]}
    ].

-type config() :: [{atom(), any()}].

-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    Apps =
        genlib_app:start_application_with(bouncer_client, [
            {service_clients, #{
                bouncer => #{
                    url => <<"http://bouncer:8022/">>,
                    retries => #{
                        'Judge' => {linear, 3, 1000},
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
                        'GetUserContext' => {linear, 3, 1000},
                        '_' => finish
                    }
                }
            }}
        ]),
    [{apps, Apps}] ++ Config.

-spec end_per_suite(config()) -> _.
end_per_suite(Config) ->
    [application:stop(App) || App <- proplists:get_value(apps, Config)],
    Config.

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(_Name, C) ->
    [{test_sup, start_mocked_service_sup()} | C].

-spec end_per_testcase(test_case_name(), config()) -> config().
end_per_testcase(_Name, C) ->
    stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%

-spec empty_judge(config()) -> _.
empty_judge(C) ->
    mock_services(
        [
            {bouncer, fun('Judge', _) -> {ok, #bdcs_Judgement{resolution = allowed}} end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(?RULESET_ID, #{}, WoodyContext).

-spec validate_default_user_fragment(config()) -> _.
validate_default_user_fragment(C) ->
    UserID = <<"someUser">>,
    mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_user_id(Fragments) of
                    UserID ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    _ ->
                        {ok, #bdcs_Judgement{resolution = forbidden}}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"user">> => bouncer_context_helpers:make_default_user_context_fragment(UserID)}},
        WoodyContext
    ).

-spec validate_user_fragment(config()) -> _.
validate_user_fragment(C) ->
    UserID = <<"someUser">>,
    mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_user_id(Fragments) of
                    UserID ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    _ ->
                        {ok, #bdcs_Judgement{resolution = forbidden}}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"user">> => bouncer_context_helpers:make_user_context_fragment(#{id => UserID})}},
        WoodyContext
    ).

-spec validate_env_fragment(config()) -> _.
validate_env_fragment(C) ->
    Time = genlib_rfc3339:format(genlib_time:unow(), second),
    mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_time(Fragments) of
                    Time ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    _ ->
                        {ok, #bdcs_Judgement{resolution = forbidden}}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"env">> => bouncer_context_helpers:make_env_context_fragment(#{now => Time})}},
        WoodyContext
    ).

-spec validate_auth_fragment(config()) -> _.
validate_auth_fragment(C) ->
    Method = <<"someMethod">>,
    mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_auth_method(Fragments) of
                    Method ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    _ ->
                        {ok, #bdcs_Judgement{resolution = forbidden}}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"auth">> => bouncer_context_helpers:make_auth_context_fragment(#{method => Method})}},
        WoodyContext
    ).

-spec validate_requester_fragment(config()) -> _.
validate_requester_fragment(C) ->
    IP = "someIP",
    mock_services(
        [
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_ip(Fragments) of
                    undefined ->
                        {ok, #bdcs_Judgement{resolution = forbidden}};
                    BinaryIP ->
                        case binary_to_list(BinaryIP) of
                            IP ->
                                {ok, #bdcs_Judgement{resolution = allowed}};
                            _ ->
                                {ok, #bdcs_Judgement{resolution = forbidden}}
                        end
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    allowed = bouncer_client:judge(
        ?RULESET_ID,
        #{fragments => #{<<"requester">> => bouncer_context_helpers:make_requester_context_fragment(#{ip => IP})}},
        WoodyContext
    ).

-spec validate_remote_user_fragment(config()) -> _.
validate_remote_user_fragment(C) ->
    UserID = <<"someUser">>,
    mock_services(
        [
            {org_management, fun('GetUserContext', _) ->
                Content = encode(#bctx_v1_ContextFragment{
                    user = #bctx_v1_User{
                        id = UserID
                    }
                }),
                {ok, {bctx_ContextFragment, v1_thrift_binary, Content}}
            end},
            {bouncer, fun('Judge', {_RulesetID, Fragments}) ->
                case get_user_id(Fragments) of
                    UserID ->
                        {ok, #bdcs_Judgement{resolution = allowed}};
                    _ ->
                        {ok, #bdcs_Judgement{resolution = forbidden}}
                end
            end}
        ],
        C
    ),
    WoodyContext = woody_context:new(),
    {ok, EncodedUserFragment} = bouncer_context_helpers:get_user_context_fragment(UserID, WoodyContext),
    allowed = bouncer_client:judge(?RULESET_ID, #{fragments => #{<<"user">> => EncodedUserFragment}}, WoodyContext).

%%

get_ip(#bdcs_Context{
    fragments = #{
        <<"requester">> := #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = Fragment
        }
    }
}) ->
    case decode(Fragment) of
        {error, _} = Error ->
            error(Error);
        #bctx_v1_ContextFragment{requester = #bctx_v1_Requester{ip = IP}} ->
            IP
    end.

get_auth_method(#bdcs_Context{
    fragments = #{
        <<"auth">> := #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = Fragment
        }
    }
}) ->
    case decode(Fragment) of
        {error, _} = Error ->
            error(Error);
        #bctx_v1_ContextFragment{auth = #bctx_v1_Auth{method = Method}} ->
            Method
    end.

get_time(#bdcs_Context{
    fragments = #{
        <<"env">> := #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = Fragment
        }
    }
}) ->
    case decode(Fragment) of
        {error, _} = Error ->
            error(Error);
        #bctx_v1_ContextFragment{env = #bctx_v1_Environment{now = Time}} ->
            Time
    end.

get_user_id(#bdcs_Context{
    fragments = #{
        <<"user">> := #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = Fragment
        }
    }
}) ->
    case decode(Fragment) of
        {error, _} = Error ->
            error(Error);
        #bctx_v1_ContextFragment{user = #bctx_v1_User{id = UserID}} ->
            UserID
    end.

decode(Content) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
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
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
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
-define(HOST_PORT, 8080).
-define(HOST_NAME, "localhost").
-define(HOST_URL, ?HOST_NAME ++ ":" ++ integer_to_list(?HOST_PORT)).

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
    Name = lists:map(fun get_service_name/1, Services),

    Port = get_random_port(),
    {ok, IP} = inet:parse_address(?HOST_IP),
    ChildSpec = woody_server:child_spec(
        {dummy, Name},
        #{
            ip => IP,
            port => Port,
            event_handler => scoper_woody_event_handler,
            handlers => lists:map(fun mock_service_handler/1, Services)
        }
    ),
    {ok, _} = supervisor:start_child(SupPid, ChildSpec),

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
    {orgmgmt_auth_context_provider_thrift, 'AuthContextProvider'};
get_service_modname(bouncer) ->
    {bouncer_decisions_thrift, 'Arbiter'}.

% TODO not so failproof, ideally we need to bind socket first and then give to a ranch listener
get_random_port() ->
    rand:uniform(32768) + 32767.

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).
