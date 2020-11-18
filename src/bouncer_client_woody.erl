-module(bouncer_client_woody).

-export([call/4]).
-export([call/5]).

-define(APP, bouncer_client).
-define(DEFAULT_DEADLINE, 5000).

%%
-type service_name() :: atom().

-spec call(service_name(), woody:func(), woody:args(), woody_context:ctx()) -> woody:result().
call(ServiceName, Function, Args, Context) ->
    EventHandler = scoper_woody_event_handler,
    call(ServiceName, Function, Args, Context, EventHandler).

-spec call(service_name(), woody:func(), woody:args(), woody_context:ctx(), woody:ev_handler()) -> woody:result().
call(ServiceName, Function, Args, Context0, EventHandler) ->
    Deadline = get_service_deadline(ServiceName),
    Context1 = set_deadline(Deadline, Context0),
    Retry = get_service_retry(ServiceName, Function),
    call(ServiceName, Function, Args, Context1, EventHandler, Retry).

call(ServiceName, Function, Args, Context, EventHandler, Retry) ->
    Url = get_service_client_url(ServiceName),
    Service = get_service_modname(ServiceName),
    Request = {Service, Function, Args},
    try
        woody_client:call(
            Request,
            #{url => Url, event_handler => EventHandler},
            Context
        )
    catch
        error:{woody_error, {_Source, Class, _Details}} = Error when
            Class =:= resource_unavailable orelse Class =:= result_unknown
        ->
            NextRetry = apply_retry_strategy(Retry, Error, Context),
            call(ServiceName, Function, Args, Context, EventHandler, NextRetry)
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

get_service_client_config(ServiceName) ->
    ServiceClients = genlib_app:env(bouncer_client, service_clients, #{}),
    maps:get(ServiceName, ServiceClients, #{}).

get_service_client_url(ServiceName) ->
    maps:get(url, get_service_client_config(ServiceName), undefined).

-spec get_service_modname(service_name()) -> woody:service().
get_service_modname(org_management) ->
    {orgmgmt_auth_context_provider_thrift, 'AuthContextProvider'};
get_service_modname(bouncer) ->
    {bouncer_decisions_thrift, 'Arbiter'}.

-spec get_service_deadline(service_name()) -> undefined | woody_deadline:deadline().
get_service_deadline(ServiceName) ->
    ServiceClient = get_service_client_config(ServiceName),
    Timeout = maps:get(deadline, ServiceClient, ?DEFAULT_DEADLINE),
    woody_deadline:from_timeout(Timeout).

set_deadline(Deadline, Context) ->
    case woody_context:get_deadline(Context) of
        undefined ->
            woody_context:set_deadline(Deadline, Context);
        _AlreadySet ->
            Context
    end.

get_service_retry(ServiceName, Function) ->
    ServiceRetries = genlib_app:env(?APP, service_retries, #{}),
    FunctionReties = maps:get(ServiceName, ServiceRetries, #{}),
    DefaultRetry = maps:get('_', FunctionReties, finish),
    maps:get(Function, FunctionReties, DefaultRetry).
