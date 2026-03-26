<cfscript>
	// Dump extension API from loaded FLD metadata to GITHUB_STEP_SUMMARY
	summaryFile = server.system.environment[ "GITHUB_STEP_SUMMARY" ] ?: "";
	if ( !len( summaryFile ) )
		throw( message="GITHUB_STEP_SUMMARY not set", detail="This script is meant to run in GitHub Actions" );

	// Use Lucee internals to find functions from our extension by class package
	cfg = getPageContext().getConfig();
	flds = cfg.getFLDs();
	ff = flds.getFunctions();
	cryptoNames = [];
	for ( fname in ff ) {
		cls = ff[ fname ].getBIF().getClass().getName();
		if ( findNoCase( "org.lucee.extension.crypto", cls ) )
			cryptoNames.append( fname );
	}
	cryptoNames.sort( "textnocase" );

	// Now get the full metadata via getFunctionData()
	md = [ "## Crypto Extension API (#cryptoNames.len()# functions)" & chr( 10 ) ];
	md.append( "| Function | Returns |" );
	md.append( "| --- | --- |" );

	lastChar = "";
	for ( fname in cryptoNames ) {
		fn = getFunctionData( fname );
		name = fn.nameWithCase ?: fn.name;
		firstChar = uCase( left( name, 1 ) );
		if ( len( lastChar ) && firstChar != lastChar )
			md.append( "| | |" );
		lastChar = firstChar;

		ret = fn.returnType ?: "void";

		args = [];
		for ( arg in ( fn.arguments ?: [] ) ) {
			argStr = arg.name & "=" & ( arg.type ?: "any" );
			args.append( argStr );
		}

		sig = "`#name#( #args.toList( ', ' )# )`";
		md.append( "| #sig# | #ret# |" );
	}

	content = md.toList( chr( 10 ) );
	fileWrite( summaryFile, content & chr( 10 ), "utf-8" );
	systemOutput( content, true );
</cfscript>
