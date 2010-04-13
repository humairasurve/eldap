{application, eldap,
        [{description, "LDAP client application"},
         {vsn, "1.4"},
         {modules, [eldap_app, eldap_sup, eldap_fsm]},
         {registered, [eldap_fsm]},
         {applications, [kernel,stdlib]},
	 {env, []},
	 {mod, {eldap_app, []}}]
}.
