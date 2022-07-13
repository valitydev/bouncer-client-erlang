-module(bouncer_client).

-include_lib("bouncer_proto/include/bouncer_decision_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").

%% API

-export([judge/3]).

-export([bake_context_fragment/1]).

%%

-type woody_context() :: woody_context:ctx().

-type context_fragment_id() :: binary().
-type ruleset_id() :: binary().
-type encoded_context_fragment() :: bouncer_ctx_thrift:'ContextFragment'().
-type context_fragment() ::
    bouncer_context_helpers:context_fragment()
    | {encoded_fragment, encoded_context_fragment()}.

-type judge_context() :: #{
    fragments => #{context_fragment_id() => context_fragment()}
}.

-type judgement() :: allowed | forbidden | {restricted, bouncer_rstn_thrift:'Restrictions'()}.

-type service_name() :: atom().

-export_type([service_name/0]).
-export_type([judgement/0]).
-export_type([judge_context/0]).
-export_type([context_fragment/0]).
-export_type([encoded_context_fragment/0]).

-spec judge(ruleset_id(), judge_context(), woody_context()) -> judgement().
judge(RulesetID, JudgeContext, WoodyContext) ->
    case judge_(RulesetID, JudgeContext, WoodyContext) of
        {ok, Judgement} ->
            Judgement;
        {error, Reason} ->
            erlang:error({bouncer_judgement_failed, Reason})
    end.

-spec judge_(ruleset_id(), judge_context(), woody_context()) ->
    {ok, judgement()}
    | {error,
        {ruleset, notfound | invalid}
        | {context, invalid}}.
judge_(RulesetID, JudgeContext, WoodyContext) ->
    Context = collect_judge_context(JudgeContext),
    case bouncer_client_woody:call(bouncer, 'Judge', {RulesetID, Context}, WoodyContext) of
        {ok, Judgement} ->
            {ok, parse_judgement(Judgement)};
        {exception, #decision_RulesetNotFound{}} ->
            {error, {ruleset, notfound}};
        {exception, #decision_InvalidRuleset{}} ->
            {error, {ruleset, invalid}};
        {exception, #decision_InvalidContext{}} ->
            {error, {context, invalid}}
    end.

%%

collect_judge_context(JudgeContext) ->
    #decision_Context{fragments = collect_fragments(JudgeContext, #{})}.

collect_fragments(#{fragments := Fragments}, Context) ->
    maps:fold(fun collect_fragments_/3, Context, Fragments);
collect_fragments(_, Context) ->
    Context.

collect_fragments_(FragmentID, {encoded_fragment, EncodedFragment}, Acc0) ->
    Acc0#{FragmentID => EncodedFragment};
collect_fragments_(FragmentID, ContextFragment = #ctx_v1_ContextFragment{}, Acc0) ->
    collect_fragments_(FragmentID, bake_context_fragment(ContextFragment), Acc0).

%%

parse_judgement(#decision_Judgement{resolution = {allowed, #decision_ResolutionAllowed{}}}) ->
    allowed;
parse_judgement(#decision_Judgement{resolution = {forbidden, #decision_ResolutionForbidden{}}}) ->
    forbidden;
parse_judgement(#decision_Judgement{
    resolution = {restricted, #decision_ResolutionRestricted{restrictions = Restrictions}}
}) ->
    {restricted, Restrictions}.

%%

-spec bake_context_fragment(bouncer_context_helpers:context_fragment()) ->
    {encoded_fragment, encoded_context_fragment()}.
bake_context_fragment(ContextFragment) ->
    {encoded_fragment, #ctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_fragment(ContextFragment)
    }}.

encode_context_fragment(ContextFragment) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.
