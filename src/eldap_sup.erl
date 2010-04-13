%%%----------------------------------------------------------------------
%%% File    : eldap_sup.erl
%%% Author  :  <shinde@CS713033>
%%% Purpose :
%%% Created :  7 Dec 2000 by  <shinde@CS713033>
%%%----------------------------------------------------------------------

-module(eldap_sup).
-author('shinde@CS713033').

%%-compile(export_all).
%%-export([Function/Arity, ...]).

-behaviour(supervisor).

%% External exports
-export([start_link/0]).

%% supervisor callbacks
-export([init/1]).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, eldap_sup}, eldap_sup, []).

%%%----------------------------------------------------------------------
%%% Callback functions from supervisor
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok,  {SupFlags,  [ChildSpec]}} |
%%          ignore                          |
%%          {error, Reason}
%%----------------------------------------------------------------------
init([]) ->
    case get_config() of
	{error, Reason} ->
	    {error, Reason};
	Configs ->
	    Childs =
		lists:map(fun({Name, Config}) ->
				  {Name,{eldap_fsm,start_link,[Name, Config]},
				   permanent,2000,worker,[eldap_fsm]}
			  end, Configs),
	    {ok,{{one_for_one,5,1}, Childs}}
    end.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------


%%% --------------------------------------------------------------------
%%% Get and Validate the initial configuration
%%% --------------------------------------------------------------------
get_config() ->
    Entries = case application:get_env(eldap, connections) of
                  {ok, V} ->
                      V;
                  undefined ->
                      []
              end,
    case catch parse(Entries) of
	{ok, Configs} ->
	    Configs;
	{error, Reason} ->
	    {error, Reason};
	{'EXIT', Reason} ->
	    {error, Reason}
    end.

parse(Entries) ->
    {ok, lists:map(fun({Name, Vals}) ->
		      {Name,
		       {get_hosts(addr, Vals),
			get_list(rootdn, Vals),
			get_list(passwd, Vals),
			get_log(log, Vals)}}
	      end, Entries)}.


get_list(Key, List) ->
    case lists:keysearch(Key, 1, List) of
	{value, {Key, Value}} when list(Value) ->
	    Value;
	{value, {Key, Value}} ->
	    throw({error, "Bad Value in Config for " ++ atom_to_list(Key)});
	false ->
	    throw({error, "No Entry in Config for " ++ atom_to_list(Key)})
    end.

get_log(Key, List) ->
    case lists:keysearch(Key, 1, List) of
	{value, {Key, Value}} when function(Value) ->
	    Value;
	{value, {Key, Else}} ->
	    false;
	false ->
	    fun(Level, Format, Args) -> io:format("--- " ++ Format, Args) end
    end.

get_hosts(Key, List) ->
    lists:foldl(fun({Key1, {{A,B,C,D}, Port}}, Acc) when integer(A),
							integer(B),
							integer(C),
							integer(D),
							Key == Key1->
			   [{{A,B,C,D}, Port}|Acc];
		 ({Key1, {Host, Port}}, Acc) when list(Host),
						  Key == Key1->
		      [{Host, Port}|Acc];
		 ({Else, Value}, Acc) ->
		      Acc
	      end, [], List).
