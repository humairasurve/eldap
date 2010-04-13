-module(eldap_fsm).
%%% --------------------------------------------------------------------
%%% Created:  12 Oct 2000 by Tobbe <tnt@home.se>
%%% Function: Erlang client LDAP implementation according RFC 2251.
%%%           The interface is based on RFC 1823, and
%%%           draft-ietf-asid-ldap-c-api-00.txt
%%%
%%% Copyright (C) 2000  Torbjörn Törnkvist, tnt@home.se
%%%
%%% This program is free software; you can redistribute it and/or modify
%%% it under the terms of the GNU General Public License as published by
%%% the Free Software Foundation; either version 2 of the License, or
%%% (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%% GNU General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


%%% Modified by Sean Hinde <shinde@iee.org> 7th Dec 2000
%%% Turned into gen_fsm, made non-blocking, added timers etc to support this.
%%% Now has the concept of a name (string() or atom()) per instance which allows
%%% multiple users to call by name if so desired.
%%%
%%% Can be configured with start_link parameters or use a config file to get
%%% host to connect to, dn, password, log function etc.
%%%
%%% It will regularly try to reconnect to each of the listed hosts in turn
%%% if the connection is lost.

%%% --------------------------------------------------------------------

%%%----------------------------------------------------------------------
%%% LDAP Client state machine.
%%% Possible states are:
%%%     connecting - actually disconnected, but retrying periodically
%%%     wait_bind_response  - connected and sent bind request
%%%     active - bound to LDAP Server and ready to handle commands
%%%----------------------------------------------------------------------

%%-compile(export_all).
%%-export([Function/Arity, ...]).

-behaviour(gen_fsm).

%% External exports
-export([start_link/2]).

-export([baseObject/0,singleLevel/0,wholeSubtree/0,close/1,
	 equalityMatch/2,greaterOrEqual/2,lessOrEqual/2,
	 approxMatch/2,search/2,search/5, substrings/2,present/1,
	 'and'/1,'or'/1,'not'/1,modify/3, mod_add/2, mod_delete/2,
	 mod_replace/2, add/3, delete/2, modify_dn/5]).
-export([debug_level/2, get_status/1, is_connected/1, status/2]).

%% gen_fsm callbacks
-export([init/1, connecting/2,
	 connecting/3, wait_bind_response/3, active/3, handle_event/3,
	 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).


-import(lists,[concat/1]).

-include("ELDAPv3.hrl").
-include("eldap.hrl").

-define(LDAP_VERSION, 3).
-define(RETRY_TIMEOUT, 5000).
-define(BIND_TIMEOUT, 10000).
-define(CMD_TIMEOUT, 5000).
-define(MAX_TRANSACTION_ID, 65535).
-define(MIN_TRANSACTION_ID, 0).
-define(timeout_count_threshold, 20).
-define(CONNECT_TIMEOUT, 10000).

-record(eldap, {version = ?LDAP_VERSION,
		hosts,	      % Possible hosts running LDAP servers
		host = null,  % Connected Host LDAP server
		fd = null,    % Socket filedescriptor.
		rootdn = "",  % Name of the entry to bind as
		passwd,       % Password for (above) entry
		id = 0,       % LDAP Request ID
		log,          % User provided log function
		bind_timer,   % Ref to bind timeout
		dict,         % dict holding operation params and results
		debug_level,  % Integer debug/logging level
		connector_pid,% Pid of spawned connector process
		timeout_count=0 % Count of successive command timeouts
	       }).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start_link(Name, {Hosts, Rootdn, Passwd}) ->
    Log = fun(N, Fmt, Args) -> io:format("---- " ++ Fmt, [Args]) end,
    gen_fsm:start_link({local, Name}, ?MODULE, {Hosts, Rootdn, Passwd, Log}, []);

start_link(Name, {Hosts, Rootdn, Passwd, Log}) ->
    gen_fsm:start_link({local, Name}, ?MODULE, {Hosts, Rootdn, Passwd, Log}, []).

%%% --------------------------------------------------------------------
%%% Set Debug Level. 0 - none, 1 - errors, 2 - ldap events
%%% --------------------------------------------------------------------
debug_level(Handle, N) when integer(N) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_all_state_event(Handle1, {debug_level,N}).

%%% --------------------------------------------------------------------
%%% Get status of connection.
%%% --------------------------------------------------------------------
get_status(Handle) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_all_state_event(Handle1, get_status, 3000).

is_connected(Handle) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_all_state_event(Handle1, is_connected, 3000).

status(Env, []) ->
    Resp = case (catch supervisor:which_children(eldap_sup)) of
	       {'EXIT', Reason} ->
		   "No LDAP Clients Running.";
	       Clients ->
		   lists:map(fun({Name0, _,_,_}) ->
				     {Name, Status} = case (catch is_connected(Name0)) of
							  {'EXIT', Reason} ->
							      {atom_to_list(Name0), "Failed"};
							  {true, {Host, Port}}->
							      {Host ++ ":" ++ integer_to_list(Port), "Connected"};
							  {true, _} ->
							      {atom_to_list(Name0), "Not Connected"};
							  {false,{Host, Port}}->
							      {Host ++ ":" ++ integer_to_list(Port),"Not Connected"};
							  {false, _} ->
							      {atom_to_list(Name0), "Not Connected"}
						      end,
				     ["<TR><TD>",Name,"</TD><TD>",Status,"</TD></TR>\n"]
			     end, Clients)
	   end,
    esp:expand("eldap.esp",[{"clients", Resp}]).

%%% --------------------------------------------------------------------
%%% Shutdown connection (and process) asynchronous.
%%% --------------------------------------------------------------------
close(Handle) ->
    Handle1 = get_handle(Handle),
    gen_fsm:send_all_state_event(Handle1, close).

%%% --------------------------------------------------------------------
%%% Add an entry. The entry field MUST NOT exist for the AddRequest
%%% to succeed. The parent of the entry MUST exist.
%%% Example:
%%%
%%%  add(Handle,
%%%         "cn=Bill Valentine, ou=people, o=Bluetail AB, dc=bluetail, dc=com",
%%%         [{"objectclass", ["person"]},
%%%          {"cn", ["Bill Valentine"]},
%%%          {"sn", ["Valentine"]},
%%%          {"telephoneNumber", ["545 555 00"]}]
%%%     )
%%% --------------------------------------------------------------------
add(Handle, Entry, Attributes) when list(Entry),list(Attributes) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_event(Handle1, {add, Entry, add_attrs(Attributes)}).

%%% Do sanity check !
add_attrs(Attrs) ->
    F = fun({Type,Vals}) when list(Type),list(Vals) ->
		%% Confused ? Me too... :-/
		{'AddRequest_attributes',Type, Vals}
	end,
    case catch lists:map(F, Attrs) of
	{'EXIT', _} -> throw({error, attribute_values});
	Else        -> Else
    end.


%%% --------------------------------------------------------------------
%%% Delete an entry. The entry consists of the DN of
%%% the entry to be deleted.
%%% Example:
%%%
%%%  delete(Handle,
%%%         "cn=Bill Valentine, ou=people, o=Bluetail AB, dc=bluetail, dc=com"
%%%        )
%%% --------------------------------------------------------------------
delete(Handle, Entry) when list(Entry) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_event(Handle1, {delete, Entry}).

%%% --------------------------------------------------------------------
%%% Modify an entry. Given an entry a number of modification
%%% operations can be performed as one atomic operation.
%%% Example:
%%%
%%%  modify(Handle,
%%%         "cn=Torbjorn Tornkvist, ou=people, o=Bluetail AB, dc=bluetail, dc=com",
%%%         [replace("telephoneNumber", ["555 555 00"]),
%%%          add("description", ["LDAP hacker"])]
%%%        )
%%% --------------------------------------------------------------------
modify(Handle, Object, Mods) when list(Object), list(Mods) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_event(Handle1, {modify, Object, Mods}).

%%%
%%% Modification operations.
%%% Example:
%%%            replace("telephoneNumber", ["555 555 00"])
%%%
mod_add(Type, Values) when list(Type), list(Values)     -> m(add, Type, Values).
mod_delete(Type, Values) when list(Type), list(Values)  -> m(delete, Type, Values).
mod_replace(Type, Values) when list(Type), list(Values) -> m(replace, Type, Values).

m(Operation, Type, Values) ->
    #'ModifyRequest_modification_SEQOF'{
       operation = Operation,
       modification = #'AttributeTypeAndValues'{
	 type = Type,
	 vals = Values}}.

%%% --------------------------------------------------------------------
%%% Modify an entry. Given an entry a number of modification
%%% operations can be performed as one atomic operation.
%%% Example:
%%%
%%%  modify_dn(Handle,
%%%    "cn=Bill Valentine, ou=people, o=Bluetail AB, dc=bluetail, dc=com",
%%%    "cn=Ben Emerson",
%%%    true,
%%%    ""
%%%        )
%%% --------------------------------------------------------------------
modify_dn(Handle, Entry, NewRDN, DelOldRDN, NewSup)
  when list(Entry),list(NewRDN),atom(DelOldRDN),list(NewSup) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_event(Handle1, {modify_dn, Entry, NewRDN, bool_p(DelOldRDN), optional(NewSup)}).

%%% Sanity checks !

bool_p(Bool) when Bool==true;Bool==false -> Bool.

optional([])    -> asn1_NOVALUE;
optional(Value) -> Value.

%%% --------------------------------------------------------------------
%%% Synchronous search of the Directory returning a
%%% requested set of attributes.
%%%
%%%  Example:
%%%
%%%	Filter = eldap:substrings("sn", [{any,"o"}]),
%%%	eldap_fsm:search(S, [{base, "dc=bluetail, dc=com"},
%%%	                 {filter, Filter},
%%%			 {attributes,["cn"]}])),
%%%
%%% Returned result:  {ok, #eldap_search_result{}}
%%%
%%% Example:
%%%
%%%  {ok,{eldap_search_result,
%%%        [{eldap_entry,
%%%           "cn=Magnus Froberg, dc=bluetail, dc=com",
%%%           [{"cn",["Magnus Froberg"]}]},
%%%         {eldap_entry,
%%%           "cn=Torbjorn Tornkvist, dc=bluetail, dc=com",
%%%           [{"cn",["Torbjorn Tornkvist"]}]}],
%%%        []}}
%%%
%%% --------------------------------------------------------------------
search(Handle, A) when record(A, eldap_search) ->
    call_search(Handle, A);
search(Handle, L) when atom(Handle), list(L) ->
    case catch parse_search_args(L) of
	{error, Emsg}                  -> {error, Emsg};
	{'EXIT', Emsg}                 -> {error, Emsg};
	A when record(A, eldap_search) -> call_search(Handle, A)
    end.

search(Handle, Base_dn, Filter_desc, Filter_val, Attributes) ->
    Handle1 = get_handle(Handle),
    A = {Base_dn, Filter_desc, Filter_val, Attributes},
    gen_fsm:sync_send_event(Handle1, {fast_search, A}).

call_search(Handle, A) ->
    Handle1 = get_handle(Handle),
    gen_fsm:sync_send_event(Handle1, {search, A}).

parse_search_args(Args) ->
    parse_search_args(Args, #eldap_search{scope = wholeSubtree}).

parse_search_args([{base, Base}|T],A) ->
    parse_search_args(T,A#eldap_search{base = Base});
parse_search_args([{filter, Filter}|T],A) ->
    parse_search_args(T,A#eldap_search{filter = Filter});
parse_search_args([{scope, Scope}|T],A) ->
    parse_search_args(T,A#eldap_search{scope = Scope});
parse_search_args([{attributes, Attrs}|T],A) ->
    parse_search_args(T,A#eldap_search{attributes = Attrs});
parse_search_args([{types_only, TypesOnly}|T],A) ->
    parse_search_args(T,A#eldap_search{types_only = TypesOnly});
parse_search_args([{timeout, Timeout}|T],A) when integer(Timeout) ->
    parse_search_args(T,A#eldap_search{timeout = Timeout});
parse_search_args([H|T],A) ->
    throw({error,{unknown_arg, H}});
parse_search_args([],A) ->
    A.

%%%
%%% The Scope parameter
%%%
baseObject()   -> baseObject.
singleLevel()  -> singleLevel.
wholeSubtree() -> wholeSubtree.

%%%
%%% Boolean filter operations
%%%
'and'(ListOfFilters) when list(ListOfFilters) -> {'and',ListOfFilters}.
'or'(ListOfFilters)  when list(ListOfFilters) -> {'or', ListOfFilters}.
'not'(Filter)        when tuple(Filter)       -> {'not',Filter}.

%%%
%%% The following Filter parameters consist of an attribute
%%% and an attribute value. Example: F("uid","tobbe")
%%%
equalityMatch(Desc, Value)   -> {equalityMatch, av_assert(Desc, Value)}.
greaterOrEqual(Desc, Value)  -> {greaterOrEqual, av_assert(Desc, Value)}.
lessOrEqual(Desc, Value)     -> {lessOrEqual, av_assert(Desc, Value)}.
approxMatch(Desc, Value)     -> {approxMatch, av_assert(Desc, Value)}.

av_assert(Desc, Value) ->
    #'AttributeValueAssertion'{attributeDesc  = Desc,
			       assertionValue = Value}.

%%%
%%% Filter to check for the presence of an attribute
%%%
present(Attribute) when list(Attribute) ->
    {present, Attribute}.


%%%
%%% A substring filter seem to be based on a pattern:
%%%
%%%   InitValue*AnyValue*FinalValue
%%%
%%% where all three parts seem to be optional (at least when
%%% talking with an OpenLDAP server). Thus, the arguments
%%% to substrings/2 looks like this:
%%%
%%% Type   ::= string( <attribute> )
%%% SubStr ::= listof( {initial,Value} | {any,Value}, {final,Value})
%%%
%%% Example: substrings("sn",[{initial,"To"},{any,"kv"},{final,"st"}])
%%% will match entries containing:  'sn: Tornkvist'
%%%
substrings(Type, SubStr) when list(Type), list(SubStr) ->
    Ss = {'SubstringFilter_substrings',v_substr(SubStr)},
    {substrings,#'SubstringFilter'{type = Type,
				   substrings = Ss}}.


get_handle(Pid) when pid(Pid)    -> Pid;
get_handle(Atom) when atom(Atom) -> Atom;
get_handle(Name) when list(Name) -> list_to_atom("eldap_" ++ Name).
%%%----------------------------------------------------------------------
%%% Callback functions from gen_fsm
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, StateName, StateData}          |
%%          {ok, StateName, StateData, Timeout} |
%%          ignore                              |
%%          {stop, StopReason}
%% I use the trick of setting a timeout of 0 to pass control into the
%% process.
%%----------------------------------------------------------------------
init({Hosts, Rootdn, Passwd, Log}) ->
    process_flag(trap_exit, true),
    {ok, connecting, #eldap{hosts = Hosts,
			    rootdn = Rootdn,
			    passwd = Passwd,
			    id = 0,
			    log = Log,
			    dict = dict:new(),
			    debug_level = 0}, 0}.

%%----------------------------------------------------------------------
%% Func: StateName/2
%% Called when gen_fsm:send_event/2,3 is invoked (async)
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------
connecting(timeout, S) ->
    {ok, NextState, NewS} = connect(S),
    {Host, Port} = NewS#eldap.host,
    alarm_handler:set_alarm({{connection_lost, eldap, Host, Port}, []}),
    {next_state, NextState, NewS}.

%%----------------------------------------------------------------------
%% Func: StateName/3
%% Called when gen_fsm:sync_send_event/2,3 is invoked.
%% Returns: {next_state, NextStateName, NextStateData}            |
%%          {next_state, NextStateName, NextStateData, Timeout}   |
%%          {reply, Reply, NextStateName, NextStateData}          |
%%          {reply, Reply, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}                          |
%%          {stop, Reason, Reply, NewStateData}
%%----------------------------------------------------------------------
connecting(Event, From, S) ->
    Reply = {error, connecting},
    {reply, Reply, connecting, S}.

wait_bind_response(Event, From, S) ->
    Reply = {error, wait_bind_response},
    {reply, Reply, wait_bind_response, S}.

active(Event, From, S) ->
    {Host, Port} = S#eldap.host,
    case catch send_command(Event, From, S) of
	{ok, NewS} ->
	    {next_state, active, NewS};
	{error, Reason} ->
	    {reply, {error, Reason}, active, S};
	{'EXIT', Reason} ->
	    {reply, {error, Reason}, active, S}
    end.

%%----------------------------------------------------------------------
%% Func: handle_event/3
%% Called when gen_fsm:send_all_state_event/2 is invoked.
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------
handle_event(close, StateName, S) ->
    gen_tcp:close(S#eldap.fd),
    {stop, closed, S};

handle_event(Event, StateName, S) ->
    {next_state, StateName, S}.

%%----------------------------------------------------------------------
%% Func: handle_sync_event/4
%% Called when gen_fsm:sync_send_all_state_event/2,3 is invoked
%% Returns: {next_state, NextStateName, NextStateData}            |
%%          {next_state, NextStateName, NextStateData, Timeout}   |
%%          {reply, Reply, NextStateName, NextStateData}          |
%%          {reply, Reply, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}                          |
%%          {stop, Reason, Reply, NewStateData}
%%----------------------------------------------------------------------
handle_sync_event({debug_level, N}, From, StateName, S) ->
    {reply, ok, StateName, S#eldap{debug_level = N}};

handle_sync_event(is_connected, From, StateName, S) ->
    case StateName of
	active ->
	    {reply, {true, S#eldap.host}, StateName, S};
	_ ->
	    {reply, {false, S#eldap.host}, StateName, S}
    end;

handle_sync_event(get_status, From, StateName, S) ->
    {reply, {StateName, S}, StateName, S};

handle_sync_event(Event, From, StateName, S) ->
    Reply = ok,
    {reply, Reply, StateName, S}.

%%----------------------------------------------------------------------
%% Func: handle_info/3
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------

%%
%% Packets arriving in various states
%%
handle_info({tcp, Socket, Data}, connecting, S) ->
    log1("eldap. tcp packet received when disconnected!~n~p~n", [Data], S),
    {next_state, connecting, S};

handle_info({tcp, Socket, Data}, wait_bind_response, S) ->
    {Host, Port} = S#eldap.host,
    cancel_timer(S#eldap.bind_timer),
    A = recvd_wait_bind_response(Data, S),
    case catch recvd_wait_bind_response(Data, S) of
	bound                -> log2("Bound", [], S),
				alarm_handler:clear_alarm({connection_lost, eldap, Host, Port}),
				{next_state, active, S};
	{fail_bind, Reason}  -> log2("Fail Bind", [Reason], S),
				close_and_retry(S),
				{next_state, connecting, S#eldap{fd = null}};
	{'EXIT', Reason}     -> log2("Bind EXIT", [Reason], S),
				close_and_retry(S),
				{next_state, connecting, S#eldap{fd = null}};
	{error, Reason}      -> log2("Bind error", [Reason], S),
				close_and_retry(S),
				{next_state, connecting, S#eldap{fd = null}}
    end;

handle_info({tcp, Socket, Data}, active, S0) ->
    {Host, Port} = S0#eldap.host,
    S = S0#eldap{timeout_count = 0},
    case catch recvd_packet(Data, S) of
	{reply, Reply, To, NewS} -> gen_fsm:reply(To, Reply),
				    {next_state, active, NewS};
	{ok, NewS}               -> {next_state, active, NewS};
	{'EXIT', Reason}         -> {next_state, active, S};
	{error, Reason}          -> {next_state, active, S}
    end;

handle_info({tcp_closed, Socket}, All_fsm_states, S) ->
    F = fun(Id, [{Timer, From, Name}|Res]) ->
		gen_fsm:reply(From, {error, tcp_closed}),
		cancel_timer(Timer)
	end,
    dict:map(F, S#eldap.dict),
    {Host, Port} = S#eldap.host,
    alarm_handler:set_alarm({{connection_lost, eldap, Host, Port}, []}),
    retry_connect(),
    {next_state, connecting, S#eldap{fd = null,
				     timeout_count = 0,
				     dict = dict:new()}};

handle_info({tcp_error, Socket, Reason}, Fsm_state, S) ->
    {Host, Port} = S#eldap.host,
    log1("eldap received tcp_error: ~p~nIn State: ~p~n", [Reason, Fsm_state], S),
    {next_state, Fsm_state, S};

%%
%% Timers
%%
handle_info({timeout, Timer, {cmd_timeout, Id}}, active, S0) ->
    Current_count = S0#eldap.timeout_count,
    if Current_count > ?timeout_count_threshold ->
	    catch gen_tcp:close(S0#eldap.fd),
	    handle_info({tcp_closed, S0#eldap.fd}, active, S0#eldap{timeout_count = 0});
       true ->
	    S = S0#eldap{timeout_count = Current_count + 1},
	    {Host, Port} = S#eldap.host,
	    case cmd_timeout(Timer, Id, S) of
		{reply, To, Reason, NewS} -> gen_fsm:reply(To, Reason),
					     {next_state, active, NewS};
		{error, Reason}           -> {next_state, active, S}
	    end
    end;

handle_info({timeout, retry_connect}, connecting, S) ->
    {ok, NextState, NewS} = connect(S),
    {next_state, NextState, NewS};

handle_info({timeout, Timer, bind_timeout}, wait_bind_response, S) ->
    close_and_retry(S),
    {next_state, connecting, S#eldap{fd = null,
				     timeout_count = 0}};

handle_info({connected, Socket, Host, Port}, connecting, S0) ->
    S = S0#eldap{fd = Socket,
		 host = {Host, Port}},
    inet:setopts(Socket, [{active, true}]),
    {ok, Next_state, NewS} = bind(S),
    {next_state, Next_state, NewS};

handle_info(connect_failed, connecting, S) ->
    {Host, Port} = S#eldap.host,
    close_and_retry(S),
    {next_state, connecting, S#eldap{fd = null,
				     timeout_count = 0}};

handle_info({'EXIT', Pid, normal}, St, #eldap{connector_pid = Pid} = S) ->
    {next_state, St, S};

handle_info({'EXIT', Pid, Reason}, connecting, #eldap{connector_pid = Pid} = S) ->
    {Host, Port} = S#eldap.host,
    close_and_retry(S),
    {next_state, connecting, S#eldap{fd = null,
				     timeout_count = 0}};

%%
%% Make sure we don't fill the message queue with rubbish
%%
handle_info(Info, StateName, S) ->
    log1("eldap. Unexpected Info: ~p~nIn state: ~p~n when StateData is: ~p~n",
			[Info, StateName, S], S),
    {next_state, StateName, S}.

%%----------------------------------------------------------------------
%% Func: terminate/3
%% Purpose: Shutdown the fsm
%% Returns: any
%%----------------------------------------------------------------------
terminate(Reason, StateName, StatData) ->
    ok.

%%----------------------------------------------------------------------
%% Func: code_change/4
%% Purpose: Convert process state when code is changed
%% Returns: {ok, NewState, NewStateData}
%%----------------------------------------------------------------------
code_change(OldVsn, StateName, S, Extra) ->
    {ok, StateName, S}.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------
send_command({fast_search, Pars}, From, S) ->
    Id = bump_id(S),
    Bytes = gen_fast_search(Pars, Id),
    ok = gen_tcp:send(S#eldap.fd, Bytes),
    Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, Id}),
    New_dict = dict:store(Id, [{Timer, From, searchRequest}], S#eldap.dict),
    {ok, S#eldap{id = Id,
		 dict = New_dict}};
send_command(Command, From, S) ->
    Id = bump_id(S),
    {Name, Request} = gen_req(Command),
    Message = #'LDAPMessage'{messageID  = Id,
			     protocolOp = {Name, Request}},
    log2("~p~n",[{Name, Request}], S),
    {ok, Bytes} = asn1rt:encode('ELDAPv3', 'LDAPMessage', Message),
    ok = gen_tcp:send(S#eldap.fd, Bytes),
    Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, Id}),
    New_dict = dict:store(Id, [{Timer, From, Name}], S#eldap.dict),
    {ok, S#eldap{id = Id,
		 dict = New_dict}}.

%% Horrible optimised search encoder. Lots if hard coded values taken
%% from real example. Ugh! About 4 times faster than normal.
%%
gen_fast_search({Base_dn, Filter_desc, Filter_val, Attributes}, Id) ->
    %% Assume we have only 1 filter not a boolean set of them. Also
    %% assumes that the attributes and so on are less than 127 octets.
    {Len, Desc} = enc_string(Filter_desc),
    {L2, Val} = enc_string(Filter_val),
    Filter_len = Len + L2 + 2,
    Filter = [163, Len+L2, Desc, Val],
    {L3, Att} = enc_attrs(Attributes, 0, []),
    Attrs_len = L3 + 2,
    Attrs = [48, L3, Att],
    {Base_dn_len, Base_dn_enc} = enc_string(Base_dn),
    Search_req_len = Base_dn_len + Filter_len + Attrs_len + 15,
    {Search_req_len_enc, Search_req_len_len} = encode_length(Search_req_len),
    Search_req = [99, Search_req_len_enc,
                  Base_dn_enc,
                  <<10,1,2,
                   10,1,0,
                   2,1,0,
                   2,1,0,
                   1,1,0>>,
                  Filter,
                  Attrs],
    Message_id = <<2,1,Id>>,
    {Proto_op_len, _Proto_op_len_len} = encode_length(3 + Search_req_len + 1 + Search_req_len_len),
    [48, Proto_op_len, Message_id, Search_req].

enc_attrs([Attr|T], Len, Acc) ->
    {Sz, Str} = enc_string(Attr),
    enc_attrs(T, Len + Sz, [Str|Acc]);
enc_attrs([], Len, Acc) ->
    {Len, lists:reverse(Acc)}.

enc_string(Str) when is_list(Str) ->
    enc_string(list_to_binary(Str));
enc_string(Str) when is_binary(Str) ->
    Sz = size(Str),
    {Sz + 2, <<4, Sz, Str/binary>>}.

encode_length(L) when L =< 16#7F ->
    {L,1};
encode_length(L) ->
    Oct = minimum_octets(L),
    Len = length(Oct),
    if
	Len =< 126 ->
	    {[ (16#80+Len) | Oct ],Len+1};
	true ->
	    exit({error,{asn1, to_long_length_oct, Len}})
    end.

%% Val must be >= 0
minimum_octets(Val) ->
    minimum_octets(Val,[]).
 minimum_octets(0,Acc) ->
    Acc;
minimum_octets(Val, Acc) ->
    minimum_octets((Val bsr 8),[Val band 16#FF | Acc]).


gen_req({search, A}) ->
    {searchRequest,
     #'SearchRequest'{baseObject   = A#eldap_search.base,
		      scope        = v_scope(A#eldap_search.scope),
		      derefAliases = neverDerefAliases,
		      sizeLimit    = 0, % no size limit
		      timeLimit    = v_timeout(A#eldap_search.timeout),
		      typesOnly    = v_bool(A#eldap_search.types_only),
		      filter       = v_filter(A#eldap_search.filter),
		      attributes   = v_attributes(A#eldap_search.attributes)
		     }};
gen_req({add, Entry, Attrs}) ->
    {addRequest,
     #'AddRequest'{entry      = Entry,
		   attributes = Attrs}};
gen_req({delete, Entry}) ->
    {delRequest, Entry};
gen_req({modify, Obj, Mod}) ->
    v_modifications(Mod),
    {modifyRequest,
     #'ModifyRequest'{object       = Obj,
		      modification = Mod}};
gen_req({modify_dn, Entry, NewRDN, DelOldRDN, NewSup}) ->
    {modDNRequest,
     #'ModifyDNRequest'{entry        = Entry,
			newrdn       = NewRDN,
			deleteoldrdn = DelOldRDN,
			newSuperior  = NewSup}}.

%%-----------------------------------------------------------------------
%% recvd_packet
%% Deals with incoming packets in the active state
%% Will return one of:
%%  {ok, NewS} - Don't reply to client yet as this is part of a search
%%               result and we haven't got all the answers yet.
%%  {reply, Result, From, NewS} - Reply with result to client From
%%  {error, Reason}
%%  {'EXIT', Reason} - Broke
%%-----------------------------------------------------------------------
recvd_packet(Pkt, S) ->
    check_tag(Pkt),
    case asn1rt:decode('ELDAPv3', 'LDAPMessage', Pkt) of
	{ok,Msg} ->
	    Op = Msg#'LDAPMessage'.protocolOp,
	    log2("~p~n",[Op], S),
	    Dict = S#eldap.dict,
	    Id = Msg#'LDAPMessage'.messageID,
	    {Timer, From, Name, Result_so_far} = get_op_rec(Id, Dict),
	    case {Name, Op} of
		{searchRequest, {searchResEntry, R}} when
		      record(R,'SearchResultEntry') ->
		    New_dict = dict:append(Id, R, Dict),
		    {ok, S#eldap{dict = New_dict}};
		{searchRequest, {searchResDone, Result}} ->
		    case Result#'LDAPResult'.resultCode of
			success ->
			    {Res, Ref} = polish(Result_so_far),
			    New_dict = dict:erase(Id, Dict),
			    cancel_timer(Timer),
			    {reply, #eldap_search_result{entries = Res,
							 referrals = Ref}, From,
			                              S#eldap{dict = New_dict}};
			Reason ->
			    New_dict = dict:erase(Id, Dict),
			    cancel_timer(Timer),
			    {reply, {error, Reason}, From, S#eldap{dict = New_dict}}
			end;
		{searchRequest, {searchResRef, R}} ->
		    New_dict = dict:append(Id, R, Dict),
		    {ok, S#eldap{dict = New_dict}};
		{addRequest, {addResponse, Result}} ->
		    New_dict = dict:erase(Id, Dict),
		    cancel_timer(Timer),
		    Reply = check_reply(Result, From),
		    {reply, Reply, From, S#eldap{dict = New_dict}};
		{delRequest, {delResponse, Result}} ->
		    New_dict = dict:erase(Id, Dict),
		    cancel_timer(Timer),
		    Reply = check_reply(Result, From),
		    {reply, Reply, From, S#eldap{dict = New_dict}};
		{modifyRequest, {modifyResponse, Result}} ->
		    New_dict = dict:erase(Id, Dict),
		    cancel_timer(Timer),
		    Reply = check_reply(Result, From),
		    {reply, Reply, From, S#eldap{dict = New_dict}};
		{modDNRequest, {modDNResponse, Result}} ->
		    New_dict = dict:erase(Id, Dict),
		    cancel_timer(Timer),
		    Reply = check_reply(Result, From),
		    {reply, Reply, From, S#eldap{dict = New_dict}};
		{OtherName, OtherResult} ->
		    New_dict = dict:erase(Id, Dict),
		    cancel_timer(Timer),
		    {reply, {error, {invalid_result, OtherName, OtherResult}},
		            From, S#eldap{dict = New_dict}}
	    end;
	Error -> Error
    end.

check_reply(#'LDAPResult'{resultCode = success}, From) ->
    ok;
check_reply(#'LDAPResult'{resultCode = Reason}, From) ->
    {error, Reason};
check_reply(Other, From) ->
    {error, Other}.

get_op_rec(Id, Dict) ->
    case dict:find(Id, Dict) of
	{ok, [{Timer, From, Name}|Res]} ->
	    {Timer, From, Name, Res};
	error ->
	    throw({error, unkown_id})
    end.

%%-----------------------------------------------------------------------
%% recvd_wait_bind_response packet
%% Deals with incoming packets in the wait_bind_response state
%% Will return one of:
%%  bound - Success - move to active state
%%  {fail_bind, Reason} - Failed
%%  {error, Reason}
%%  {'EXIT', Reason} - Broken packet
%%-----------------------------------------------------------------------
recvd_wait_bind_response(Pkt, S) ->
    check_tag(Pkt),
    case asn1rt:decode('ELDAPv3', 'LDAPMessage', Pkt) of
	{ok,Msg} ->
	    log2("~p", [Msg], S),
	    check_id(S#eldap.id, Msg#'LDAPMessage'.messageID),
	    case Msg#'LDAPMessage'.protocolOp of
		{bindResponse, Result} ->
		    case Result#'BindResponse'.resultCode of
			success -> bound;
			Error   -> {fail_bind, Error}
		    end
	    end;
	Else ->
	    log2("Bind Failed~p", [Else], S),
	    {fail_bind, Else}
    end.

check_id(Id, Id) -> ok;
check_id(_, _)   -> throw({error, wrong_bind_id}).

%%-----------------------------------------------------------------------
%% General Helpers
%%-----------------------------------------------------------------------

cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    receive
	{timeout, Timer, _} ->
	    ok
    after 0 ->
	    ok
    end.


%%% Sanity check of received packet
check_tag(Data) ->
    case asn1rt_ber_bin:decode_tag(Data) of
	{Tag, Data1, Rb} ->
	    case asn1rt_ber_bin:decode_length(Data1) of
		{{Len,Data2}, Rb2} -> ok;
		_ -> throw({error,decoded_tag_length})
	    end;
	_ -> throw({error,decoded_tag})
    end.

close_and_retry(S) ->
    sock_close(S#eldap.fd),
    retry_connect().

retry_connect() ->
    erlang:send_after(?RETRY_TIMEOUT, self(),
		      {timeout, retry_connect}).

sock_close(null) ->
    ok;
sock_close(Fd) ->
    gen_tcp:close(Fd).

%%-----------------------------------------------------------------------
%% Sort out timed out commands
%%-----------------------------------------------------------------------
cmd_timeout(Timer, Id, S) ->
    Dict = S#eldap.dict,
    case dict:find(Id, Dict) of
	{ok, [{Timer, From, Name}|Res]} ->
	    case Name of
		searchRequest ->
		    {Res1, Ref1} = polish(Res),
		    New_dict = dict:erase(Id, Dict),
		    {reply, From, {timeout,
				   #eldap_search_result{entries = Res1,
							referrals = Ref1}},
		                   S#eldap{dict = New_dict}};
		Others ->
		    New_dict = dict:erase(Id, Dict),
		    {reply, From, {error, timeout}, S#eldap{dict = New_dict}}
	    end;
	error ->
	    {error, timed_out_cmd_not_in_dict}
    end.

%%-----------------------------------------------------------------------
%% Common stuff for results
%%-----------------------------------------------------------------------
%%%
%%% Polish the returned search result
%%%

polish(Entries) ->
    polish(Entries, [], []).

polish([H|T], Res, Ref) when record(H, 'SearchResultEntry') ->
    ObjectName = H#'SearchResultEntry'.objectName,
    F = fun({_,A,V}) -> {A,V} end,
    Attrs = lists:map(F, H#'SearchResultEntry'.attributes),
    polish(T, [#eldap_entry{object_name = ObjectName,
			    attributes  = Attrs}|Res], Ref);
polish([H|T], Res, Ref) ->     % No special treatment of referrals at the moment.
    polish(T, Res, [H|Ref]);
polish([], Res, Ref) ->
    {Res, Ref}.

%%-----------------------------------------------------------------------
%% Connect to next server in list and attempt to bind to it.
%%-----------------------------------------------------------------------
connect(S) ->
    {Host, Port} = next_host(S#eldap.host, S#eldap.hosts),
    TcpOpts = [{packet, asn1}, {active, false}, binary],
    Server = self(),
    Pid = spawn_link(fun() ->
			     do_connect(Host, Port, TcpOpts, Server)
		     end),
    {ok, connecting, S#eldap{connector_pid = Pid,
			     host = {Host, Port}}}.

do_connect(Host, Port, TcpOpts, Server) ->
    case gen_tcp:connect(Host, Port, TcpOpts, ?CONNECT_TIMEOUT) of
	{ok, Socket} ->
	    gen_tcp:controlling_process(Socket, Server),
	    Server ! {connected, Socket, Host, Port};
	_ ->
	    Server ! connect_failed
    end.

bind(S) ->
    case bind_request(S#eldap.fd, S) of
	{ok, NewS} ->
	    Timer = erlang:start_timer(?BIND_TIMEOUT, self(),
				       {timeout, bind_timeout}),
	    {ok, wait_bind_response, NewS#eldap{bind_timer = Timer}};
	{error, Reason} ->
	    gen_tcp:close(S#eldap.fd),
	    erlang:send_after(?RETRY_TIMEOUT, self(),
			      {timeout, retry_connect}),
	    {ok, connecting, S}
    end.

bind_request(Socket, S) ->
    Id = bump_id(S),
    Req = #'BindRequest'{version        = S#eldap.version,
			 name           = S#eldap.rootdn,
			 authentication = {simple, S#eldap.passwd}},
    Message = #'LDAPMessage'{messageID  = Id,
			     protocolOp = {bindRequest, Req}},
    log2("Message:~p~n",[Message], S),
    {ok, Bytes} = asn1rt:encode('ELDAPv3', 'LDAPMessage', Message),
    ok = gen_tcp:send(Socket, Bytes),
    {ok, S#eldap{id = Id}}.

%% Given last tried Server, find next one to try
next_host(null, [H|_]) -> H;			% First time, take first
next_host(Host, Hosts) ->			% Find next in turn
    next_host(Host, Hosts, Hosts).

next_host(Host, [Host], Hosts) -> hd(Hosts);	% Wrap back to first
next_host(Host, [Host|Tail], Hosts) -> hd(Tail);	% Take next
next_host(Host, [], Hosts) -> hd(Hosts);	% Never connected before? (shouldn't happen)
next_host(Host, [H|T], Hosts) -> next_host(Host, T, Hosts).


%%% --------------------------------------------------------------------
%%% Verify the input data
%%% --------------------------------------------------------------------

v_filter({'and',L})           -> {'and',L};
v_filter({'or', L})           -> {'or',L};
v_filter({'not',L})           -> {'not',L};
v_filter({equalityMatch,AV})  -> {equalityMatch,AV};
v_filter({greaterOrEqual,AV}) -> {greaterOrEqual,AV};
v_filter({lessOrEqual,AV})    -> {lessOrEqual,AV};
v_filter({approxMatch,AV})    -> {approxMatch,AV};
v_filter({present,A})         -> {present,A};
v_filter({substrings,S}) when record(S,'SubstringFilter') -> {substrings,S};
v_filter(_Filter) -> throw({error,concat(["unknown filter: ",_Filter])}).

v_modifications(Mods) ->
    F = fun({_,Op,_}) ->
		case lists:member(Op,[add,delete,replace]) of
		    true -> true;
		    _    -> throw({error,{mod_operation,Op}})
		end
	end,
    lists:foreach(F, Mods).

v_substr([{Key,Str}|T]) when list(Str),Key==initial;Key==any;Key==final ->
    [{Key,Str}|v_substr(T)];
v_substr([H|T]) ->
    throw({error,{substring_arg,H}});
v_substr([]) ->
    [].
v_scope(baseObject)   -> baseObject;
v_scope(singleLevel)  -> singleLevel;
v_scope(wholeSubtree) -> wholeSubtree;
v_scope(_Scope)       -> throw({error,concat(["unknown scope: ",_Scope])}).

v_bool(true)  -> true;
v_bool(false) -> false;
v_bool(_Bool) -> throw({error,concat(["not Boolean: ",_Bool])}).

v_timeout(I) when integer(I), I>=0 -> I;
v_timeout(_I) -> throw({error,concat(["timeout not positive integer: ",_I])}).

v_attributes(Attrs) ->
    F = fun(A) when list(A) -> A;
	   (A) -> throw({error,concat(["attribute not String: ",A])})
	end,
    lists:map(F,Attrs).


%%% --------------------------------------------------------------------
%%% Other Stuff
%%% --------------------------------------------------------------------
bump_id(#eldap{id = Id}) when Id > ?MAX_TRANSACTION_ID ->
    ?MIN_TRANSACTION_ID;
bump_id(#eldap{id = Id}) ->
    Id + 1.

%%% --------------------------------------------------------------------
%%% Log routines. Call a user provided log routine Fun.
%%% --------------------------------------------------------------------

log1(Str, Args, #eldap{log = Fun, debug_level = N}) -> log(Fun, Str, Args, 1, N).
log2(Str, Args, #eldap{log = Fun, debug_level = N}) -> log(Fun, Str, Args, 2, N).

log(Fun, Str, Args, This_level, Status) when function(Fun), This_level =< Status ->
    catch Fun(This_level, Str, Args);
log(_, _, _, _, _) ->
    ok.
