import java.text.SimpleDateFormat
import java.text.DateFormat
import org.apache.commons.lang.StringEscapeUtils
import org.apache.commons.lang.StringUtils
import com.branegy.service.connection.api.ConnectionService
import com.branegy.dbmaster.connection.ConnectionProvider
import com.branegy.service.core.QueryRequest
import com.branegy.dbmaster.connection.NonJdbcConnectionApiException

import io.dbmaster.tools.LdapSearch
import io.dbmaster.tools.LdapUserCache
import groovy.sql.Sql


connectionSrv = dbm.getService(ConnectionService.class)

def dbConnections

if (p_connection_query!=null) {                        
    dbConnections = connectionSrv.getConnectionSlice(new QueryRequest(p_connection_query))
} else {
    dbConnections  = connectionSrv.getConnectionList()
}


println """<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js" defer></script>"""
println """<script src="https://cdnjs.cloudflare.com/ajax/libs/floatthead/2.0.3/jquery.floatThead.min.js" defer></script>"""
def inlineScriptBase64 = """
\$(function(){
   \$('body table.simple-table').floatThead();
});
""".bytes.encodeBase64();
println """<script src="data:text/javascript;base64,${inlineScriptBase64}" defer></script>"""


println """<table cellspacing="0" class="simple-table" border="1">"""
println """<thead><tr style="background-color:#EEE">"""
println "<th>Server</th>"
println "<th>Principal Name</th>"
println "<th>Principal Type</th>"
println "<th>Principal Status in SQL Server</th>" 
println "<th>Active Directory Status</th>" 
println "<th>SID</th>" 
println "</tr></thead>" 


ldap = new LdapUserCache(dbm, logger)
ldap.loadLdapAccounts(connectionSrv)

def bytesToHex = { bytes ->
    def HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return (new String(hexChars));
}


dbConnections.each { connectionInfo ->
    def serverName = connectionInfo.getName()
    try {
        def connection = ConnectionProvider.get().getJdbcConnection(connectionInfo);
        logger.info("Connecting to ${serverName}")
        dbm.closeResourceOnExit(connection)

        new Sql(connection).eachRow("""SELECT principal_id, sid, name, type_desc, is_disabled
                                       FROM sys.server_principals 
                                       WHERE type_desc IN ('WINDOWS_LOGIN','WINDOWS_GROUP')
                                       ORDER BY type_desc, name""")
        { row ->

            principal_name = row.name

            def parts = principal_name.split("\\\\", 2)
            if (parts.length==2) {
                def domain = parts[0]
                def username = parts[1]
                // logger.debug("Domain=${domain} user=${username} ${bytesToHex(row.sid)} ${row.sid} ${row.sid.getClass().getName()}")
                    
                if (!["BUILTIN","NT AUTHORITY","NT SERVICE"].contains(domain.toUpperCase())) { 
                    def sid = bytesToHex(row.sid) 
                    def ldap_account = ldap.ldapAccountBySid[sid]

                    def disabled = false
                    if (row.is_disabled instanceof Boolean) {
                        disabled = row.is_disabled
                    } else {
                        disabled = new Boolean(1 == row.is_disabled)
                    }
                    boolean showRow = false
                    String  message
                    if (ldap_account==null) {
						showRow = true

						ldap_account = ldap.ldapAccountByName[principal_name]
						if (ldap_account==null) {
							message = "LDAP Account not found."
						} else {
							message = "Account not found by sid, but found by name with<br/> SID " + ldap_account.sidStr + "<br/> hex="+ldap_account.sidHex
						}
            
                    }  else {
						if  (ldap_account.accountControl!=null) {
							def status2 = Long.parseLong(ldap_account.accountControl)
                            if ((status2  & 0x0002) >0 ) {
								message = "Account disabled in AD" 
								showRow = true
							}
						}

						if  (!ldap_account.name.equalsIgnoreCase(username)) {
							message = "Account name in sql does not match one in AD: " +  ldap_account.name
							showRow = true
						}
                    }
                    
					if (showRow) {
                        println "<tr>"
                        println "<td>${serverName}</td>"
                        println "<td>${row.name}</td>"
                        println "<td>${row.type_desc}</td>"
                        println "<td>${disabled ? 'disabled' : 'enabled'}</td>" 
                        println "<td>${message}</td>"   
                        println "<td>${sid}</td>"   
                        println "</tr>"
                    }
                }
            }
         }
    } catch (NonJdbcConnectionApiException e) {
        logger.info("Skipping checks for connection ${serverName} as it is not a database one")
        return
    } catch (Exception e) {
        def msg = "Error occurred "+e.getMessage()
        org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e);
        logger.error(msg, e)
    }
}

println "</tbody></table>"
