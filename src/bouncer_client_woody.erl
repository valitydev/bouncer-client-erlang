-module(bouncer_client_woody).

-export([call/4]).
-export([call/5]).

-define(DEFAULT_DEADLINE, 5000).

%%

-type service_name() ::
    org_management
    | bouncer.

-type client_config() :: #{
    url := woody:url(),
    timeout => non_neg_integer(),
    retries => #{woody:func() | '_' => genlib_retry:strategy()}
}.

-type context() :: woody_context:ctx().

-spec call(service_name(), woody:func(), woody:args(), context()) -> woody:result().
call(ServiceName, Function, Args, Context) ->
    EventHandler = scoper_woody_event_handler,
    call(ServiceName, Function, Args, Context, EventHandler).

-spec call(service_name(), woody:func(), woody:args(), context(), woody:ev_handler()) -> woody:result().
call(ServiceName, Function, Args, Context0, EventHandler) ->
    Config = get_service_client_config(ServiceName),
    Deadline = get_service_deadline(Config),
    Context1 = set_deadline(Deadline, set_default_deadline(Context0)),
    Retry = get_service_retry(Function, Config),
    Service = get_service_modname(ServiceName),
    Request = {Service, Function, Args},
    Opts = #{
        url => get_service_client_url(Config),
        event_handler => EventHandler
    },
    call_retry(Request, Context1, Opts, Retry).

call_retry(Request, Context, Opts, Retry) ->
    try
        woody_client:call(Request, Opts, Context)
    catch
        error:{woody_error, {_Source, Class, _Details}} = Error when
            Class =:= resource_unavailable orelse Class =:= result_unknown
        ->
            NextRetry = apply_retry_strategy(Retry, Error, Context),
            call_retry(Request, Context, Opts, NextRetry)
    end.

apply_retry_strategy(Retry, Error, Context) ->
    apply_retry_step(genlib_retry:next_step(Retry), woody_context:get_deadline(Context), Error).

apply_retry_step(finish, _, Error) ->
    erlang:error(Error);
apply_retry_step({wait, Timeout, Retry}, undefined, _) ->
    ok = timer:sleep(Timeout),
    Retry;
apply_retry_step({wait, Timeout, Retry}, Deadline0, Error) ->
    Deadline1 = woody_deadline:from_unixtime_ms(
        woody_deadline:to_unixtime_ms(Deadline0) - Timeout
    ),
    case woody_deadline:is_reached(Deadline1) of
        true ->
            % no more time for retries
            erlang:error(Error);
        false ->
            ok = timer:sleep(Timeout),
            Retry
    end.

-spec get_service_client_config(service_name()) -> client_config().
get_service_client_config(ServiceName) ->
    ServiceClients = genlib_app:env(bouncer_client, service_clients, #{}),
    maps:get(ServiceName, ServiceClients, #{}).

get_service_client_url(ClientConfig) ->
    maps:get(url, ClientConfig).

-spec get_service_modname(service_name()) -> woody:service().
get_service_modname(org_management) ->
    {orgmgmt_authctx_provider_thrift, 'AuthContextProvider'};
get_service_modname(bouncer) ->
    {bouncer_decision_thrift, 'Arbiter'}.

-spec get_service_deadline(client_config()) -> undefined | woody_deadline:deadline().
get_service_deadline(ClientConfig) ->
    case maps:get(timeout, ClientConfig, undefined) of
        undefined -> undefined;
        Timeout -> woody_deadline:from_timeout(Timeout)
    end.

set_deadline(undefined, Context) ->
    Context;
set_deadline(Deadline, Context) ->
    woody_context:set_deadline(Deadline, Context).

set_default_deadline(Context) ->
    case woody_context:get_deadline(Context) of
        undefined ->
            woody_context:set_deadline(woody_deadline:from_timeout(?DEFAULT_DEADLINE), Context);
        _AlreadySet ->
            Context
    end.

get_service_retry(Function, ClientConfig) ->
    FunctionRetries = maps:get(retries, ClientConfig, #{}),
    DefaultRetry = maps:get('_', FunctionRetries, finish),
    maps:get(Function, FunctionRetries, DefaultRetry).
