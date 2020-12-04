-module(bouncer_context_helpers).

-include_lib("bouncer_proto/include/bouncer_decisions_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_thrift.hrl").

-export([empty/0]).
-export([make_env_fragment/1]).
-export([add_env/2]).
-export([make_auth_fragment/1]).
-export([add_auth/2]).
-export([make_user_fragment/1]).
-export([add_user/2]).
-export([make_requester_fragment/1]).
-export([add_requester/2]).

-export([get_user_orgs_fragment/2]).

-type id() :: binary().
-type method() :: binary().
-type email() :: binary().
-type timestamp() :: binary().
-type ip() :: inet:ip_address() | string() | binary().
-type context_fragment() :: bouncer_context_v1_thrift:'ContextFragment'().
-type woody_context() :: woody_context:ctx().

-type entity() :: #{
    id := id()
}.

-type environment_params() :: #{
    now => timestamp(),
    deployment => deployment()
}.

-type deployment() :: #{
    id => id()
}.

-type auth_params() :: #{
    method := method(),
    scope => [auth_scope()],
    expiration => timestamp()
}.

-type auth_scope() :: #{
    party => entity(),
    shop => entity(),
    invoice => entity()
}.

-type user_params() :: #{
    id := id(),
    realm := entity(),
    email => email(),
    orgs => [user_org()]
}.

-type user_org() :: #{
    id => id(),
    owner => entity(),
    roles => [user_role()]
}.

-type user_role() :: #{
    id => id(),
    scope => user_scope()
}.

-type user_scope() :: #{
    shop => entity()
}.

-type requester_params() :: #{
    ip => ip()
}.

-export_type([context_fragment/0]).

-export_type([environment_params/0]).
-export_type([auth_params/0]).
-export_type([user_params/0]).
-export_type([requester_params/0]).

-spec empty() -> context_fragment().
empty() ->
    #bctx_v1_ContextFragment{}.

-spec make_env_fragment(environment_params()) -> context_fragment().
make_env_fragment(Params) ->
    add_env(Params, empty()).

-spec add_env(environment_params(), context_fragment()) -> context_fragment().
add_env(Params, ContextFragment = #bctx_v1_ContextFragment{env = undefined}) ->
    Now = maybe_get_param(now, Params, genlib_rfc3339:format(genlib_time:unow(), second)),
    Deployment = maybe_get_param(deployment, Params),
    DeploymentID = maybe_get_param(id, Deployment),
    ContextFragment#bctx_v1_ContextFragment{
        env = #bctx_v1_Environment{
            now = Now,
            deployment = maybe_add_param(#bctx_v1_Deployment{id = DeploymentID}, Deployment)
        }
    }.

-spec make_auth_fragment(auth_params()) -> context_fragment().
make_auth_fragment(Params) ->
    add_auth(Params, empty()).

-spec add_auth(auth_params(), context_fragment()) -> context_fragment().
add_auth(Params, ContextFragment = #bctx_v1_ContextFragment{auth = undefined}) ->
    Method = get_param(method, Params),
    Scope = maybe_get_param(scope, Params),
    Expiration = maybe_get_param(expiration, Params),
    ContextFragment#bctx_v1_ContextFragment{
        auth = #bctx_v1_Auth{
            method = Method,
            scope = maybe_marshal_auth_scopes(Scope),
            expiration = Expiration
        }
    }.

-spec make_user_fragment(user_params()) -> context_fragment().
make_user_fragment(Params) ->
    add_user(Params, empty()).

-spec add_user(user_params(), context_fragment()) -> context_fragment().
add_user(Params, ContextFragment = #bctx_v1_ContextFragment{user = undefined}) ->
    UserID = get_param(id, Params),
    RealmEntity = get_param(realm, Params),
    Email = maybe_get_param(email, Params),
    Orgs = maybe_get_param(orgs, Params),
    ContextFragment#bctx_v1_ContextFragment{
        user = #bctx_v1_User{
            id = UserID,
            realm = marshal_entity(RealmEntity),
            email = Email,
            orgs = maybe_add_param(maybe_marshal_user_orgs(Orgs), Orgs)
        }
    }.

-spec make_requester_fragment(requester_params()) -> context_fragment().
make_requester_fragment(Params) ->
    add_requester(Params, empty()).

-spec add_requester(requester_params(), context_fragment()) -> context_fragment().
add_requester(Params, ContextFragment = #bctx_v1_ContextFragment{requester = undefined}) ->
    IP = maybe_get_param(ip, Params),
    ContextFragment#bctx_v1_ContextFragment{
        requester = #bctx_v1_Requester{
            ip = maybe_marshal_ip(IP)
        }
    }.

-spec get_user_orgs_fragment(id(), woody_context()) -> {ok, context_fragment()} | {error, {user, notfound}}.
get_user_orgs_fragment(UserID, WoodyContext) ->
    ServiceName = org_management,
    case bouncer_client_woody:call(ServiceName, 'GetUserContext', {UserID}, WoodyContext) of
        {ok, EncodedFragment} ->
            {ok, {encoded_fragment, convert_fragment(ServiceName, EncodedFragment)}};
        {exception, {orgmgmt_UserNotFound}} ->
            {error, {user, notfound}}
    end.

%%

convert_fragment(org_management, {bctx_ContextFragment, Type = v1_thrift_binary, Content}) when is_binary(Content) ->
    #bctx_ContextFragment{
        type = Type,
        content = Content
    }.

get_param(Key, Map = #{}) ->
    maps:get(Key, Map).

maybe_get_param(_Key, undefined) ->
    undefined;
maybe_get_param(Key, Map) ->
    maps:get(Key, Map, undefined).

maybe_get_param(_Key, undefined, Default) ->
    Default;
maybe_get_param(Key, Map, Default) ->
    maps:get(Key, Map, Default).

maybe_add_param(_Value, undefined) ->
    undefined;
maybe_add_param(Value, _Param) ->
    Value.

marshal_entity(Entity) ->
    EntityID = get_param(id, Entity),
    #bctx_v1_Entity{id = EntityID}.

maybe_marshal_entity(undefined) ->
    undefined;
maybe_marshal_entity(Entity) ->
    EntityID = maybe_get_param(id, Entity),
    #bctx_v1_Entity{id = EntityID}.

maybe_marshal_auth_scopes(undefined) ->
    undefined;
maybe_marshal_auth_scopes(Scopes) ->
    lists:map(fun(Scope) -> maybe_marshal_auth_scope(Scope) end, Scopes).

maybe_marshal_auth_scope(Scope) ->
    PartyEntity = maybe_get_param(party, Scope),
    ShopEntity = maybe_get_param(shop, Scope),
    InvoiceEntity = maybe_get_param(invoice, Scope),
    #bctx_v1_AuthScope{
        party = maybe_add_param(maybe_marshal_entity(PartyEntity), PartyEntity),
        shop = maybe_add_param(maybe_marshal_entity(ShopEntity), ShopEntity),
        invoice = maybe_add_param(maybe_marshal_entity(InvoiceEntity), InvoiceEntity)
    }.

maybe_marshal_user_orgs(undefined) ->
    undefined;
maybe_marshal_user_orgs(Orgs) ->
    lists:map(fun(Org) -> maybe_marshal_user_org(Org) end, Orgs).

maybe_marshal_user_org(Org) ->
    ID = maybe_get_param(id, Org),
    OwnerEntity = maybe_get_param(owner, Org),
    Roles = maybe_get_param(roles, Org),

    #bctx_v1_Organization{
        id = ID,
        owner = maybe_add_param(maybe_marshal_entity(OwnerEntity), OwnerEntity),
        roles = maybe_add_param(maybe_marshal_user_roles(Roles), Roles)
    }.

maybe_marshal_user_roles(undefined) ->
    undefined;
maybe_marshal_user_roles(Roles) ->
    lists:map(fun(Role) -> maybe_marshal_user_role(Role) end, Roles).

maybe_marshal_user_role(Role) ->
    ID = maybe_get_param(id, Role),
    Scope = maybe_get_param(scope, Role),
    ShopEntity = maybe_get_param(shop, Scope),

    #bctx_v1_OrgRole{
        id = ID,
        scope = maybe_add_param(
            #bctx_v1_OrgRoleScope{
                shop = maybe_add_param(maybe_marshal_entity(ShopEntity), ShopEntity)
            },
            Scope
        )
    }.

maybe_marshal_ip(IP) when is_tuple(IP) ->
    list_to_binary(inet:ntoa(IP));
maybe_marshal_ip(IP) when is_list(IP) ->
    list_to_binary(IP);
maybe_marshal_ip(undefined) ->
    undefined.
