<cfcomponent output="false">
	
<!---
Copyright 2007 Kyle D. Hayes

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See Release notes for information
--->
	
	<cfset variables.instance = structNew() />
	<cfset variables.instance._username = "" />
	<cfset variables.instance._password = "" />
	<cfset variables.pownceRootURI = "http://pownce.com" />
	<cfset variables.pownceLoginPath = "/api/login/" />
	<cfset variables.pownceNotesPath = "/api/notes/for/" />
	
	
	<cffunction name="init" access="public" returntype="cfpownce">
		<cfargument name="pownceUsername" type="string" required="true" />
		<cfargument name="powncePassword" type="string" required="true" />
		
		<cfset variables.instance._username = arguments.pownceUsername />
		<cfset variables.pownceNotesPath = variables.pownceNotesPath & variables.instance._username & "/" />
		<cfset variables.instance._password = arguments.powncePassword />

		<cfreturn this />
	</cffunction>
	

	<cffunction name="getNotes" access="public" returntype="xml">		
		<cfset var pToken = getPownceToken() />
		<cfset var nonce = createNonce() />
		<cfset var ts = createTimestamp() />
		<cfset var digest = getDigest(pToken, nonce, ts) />
		<cfset var authStr = getAuthString(digest, nonce, ts) />
		<cfhttp method="POST" url="#getNotesPath()#">			
			<cfhttpparam name="Content-Type" value="application/x-www-urlencoded" type="header" />
			<cfhttpparam name="User-agent" type="header" value="CFPownce/0.1 +http://kylehayes.info/" />
			<cfhttpparam name="auth" type="URL" value='#authStr#'>
		</cfhttp>
		<cfreturn xmlParse(cfhttp.fileContent) />
	</cffunction>
	
	
	<cffunction name="getPownceToken" access="private" returntype="string">
		<cfset var hashedLogin = "Basic " & toBase64(variables.instance._username & ':' & variables.instance._password) />
		<cfset var token  = ""/>
		<cfhttp method="GET" url="#getLoginPath()#">
			<cfhttpparam name="Authorization" type="header" value="#hashedLogin#" />
			<cfhttpparam name="User-agent" type="header" value="CFPownce/0.1 +http://kylehayes.info/" />
		</cfhttp>
		
		<cftry>
			<cfset token = xmlParse(cfhttp.FileContent).login.XmlAttributes.token />
			<cfcatch type="any" />
		</cftry>
		
		<cfreturn token />
	</cffunction>
	
	
	<cffunction name="getDigest" access="private" returntype="string">
		<cfargument name="pownceToken" default="" />
		<cfargument name="nonce" default="" />
		<cfargument name="timestamp" default="" />
		<cfset var digest = toBase64(binaryDecode(hash(arguments.nonce & arguments.timestamp & arguments.pownceToken,"SHA-1"),"hex")) />
		<cfreturn digest />	
	</cffunction>
	
	
	<cffunction name="getAuthString" access="private" returntype="string">
		<cfargument name="digest" default="" />
		<cfargument name="nonce" default="" />
		<cfargument name="timestamp" default="" />
		<cfset auth = 'UsernameToken Username="#variables.instance._username#", PasswordDigest="#arguments.digest#", Nonce="#arguments.nonce#", Created="#arguments.timestamp#"' />
		<cfreturn auth />
	</cffunction>
	
	
	<cffunction name="createNonce" access="private" returntype="string">
		<cfreturn toBase64(getTickCount()) />
	</cffunction>
	
	
	<cffunction name="createTimestamp" access="private" returntype="string">
		<cfreturn "#DateFormat(Now(),'yyyy-mm-dd')#T#TimeFormat(now(),'HH:mm:ss')#Z" />
	</cffunction>
	
	
	<cffunction name="getLoginPath" access="private" returntype="string">
		<cfreturn variables.pownceRootURI & variables.pownceLoginPath />
	</cffunction>
	
	
	<cffunction name="getNotesPath" access="private" returntype="string">
		<cfreturn variables.pownceRootURI & variables.pownceNotesPath />
	</cffunction>
				
</cfcomponent>