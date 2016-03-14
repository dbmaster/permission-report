import java.text.SimpleDateFormat
import java.text.DateFormat
import org.apache.commons.lang.StringEscapeUtils
import org.apache.commons.lang.StringUtils


def getNotNull(Object o) {
    if (o instanceof Date) {
        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).format(o)
    }
    return o == null? "" : o.toString()
}

def printMembers (report, account, level ) {
    if (account==null || account.members==null) {
        return
    }
    
    def members  = []
    account.members.each { member_dn ->
        def member = report.ldap.ldapAccountByDN[member_dn]
        if (member == null) {
            logger.warn("Account for ${member_dn} does not exist")
        } else {
            members.add ( member )
        }
    }
    members.sort { (it.title ?: "").toUpperCase() }
    members.each {  member ->
        def disabled = member.accountControl!=null && ((Long.parseLong(member.accountControl)  & 0x0002) >0)
        print   StringUtils.repeat("&nbsp;&nbsp;", level*2)
        
        if (disabled) print "<span title=\"disabled\" style=\"color:#d3d3d3;\">"
        print """${member.title} (${member.domain}\\${member.name})"""       
        if (disabled)  print "</span>"
        println "<br/>"
        printMembers(report, member, level+1)
    }
}

def report = new PermissionReport(dbm, logger)
def result = report.getPrincipals(p_servers)

println "<h1>Server-Level Permission</h1>"

println """<table cellspacing="0" class="simple-table" border="1">"""
println """<tr style="background-color:#EEE">"""
println "<td>Server</td>"
println "<td>Principal Name</td>"
println "<td>Principal Type</td>"
println "<td>Principal Status</td>" 
println "<td>Server Roles</td>"
println "<td>Account Info (AD/LDAP)</td>"
println "<td>Members</td>"
println "</tr>"

p_servers.each { serverName ->
    def serverPrincipals = result["${serverName}_principals"]
    serverPrincipals.each { principalName, principal ->
        println "<tr><td>${serverName}</td>"
        print "<td>${principalName}</td>"        
        println "<td>${getNotNull(principal.principal_type)}</td>"
        print "<td>${principal.disabled == null ? "" : (principal.disabled ? "disabled" : "enabled" )}</td>"
        println "<td>${principal.server_roles.join("<br/>")}</td>"
        if (principal.ldap_account!=null) {
        
            print """<td>Title: ${principal.ldap_account.title}<br/>"""
            if (principal.ldap_account.accountControl!=null) {
                println "Account Status:<br/>"
                PermissionReport.printAccountStatus(principal.ldap_account.accountControl)
            }
            
            println "<td>"
            printMembers(report, principal.ldap_account, 0)
            println "</td>"        
        } else {
            println "<td></td><td></td>"
        }
        println "</tr>"
    }
}
println "</table>"




if (p_group_by=="Principal") {
/*    
    println """<table cellspacing="0" class="simple-table" border="1">"""
    println """<tr style="background-color:#EEE">"""
    println "<td>Server</td>"
    println "<td>Principal</td>"
    println "<td>Principal Status</td>"
    println "<td>Type</td>"
    println "<td>Server Roles</td>"
    println "<td>Database Permissions</td>"
    println "<td>Account Info</td>"
    println "<td>Members</td>"
    println "</tr>"

    
    result.each { principal ->
        println "<tr valign=\"top\">"
        println "<td>${principal.connection_name}</td>"    
        print "<td>${principal.principal_name}</td>"
        println "<td>${principal.disabled == null ? "" : (principal.disabled ? "disabled" : "enabled" )}</td>"
        println "<td>${getNotNull(principal.principal_type)}</td>"
        println "<td>${principal.server_roles.join("<br/>")}</td>"
        println "<td>${principal.db_roles.collect { it.db+":"+it.role }.sort { it }.join("<br/>")}</td>"
        if (principal.ldap_account!=null) {
        
            print """<td>Title: ${principal.ldap_account.title}<br/>"""
            if (principal.ldap_account.accountControl!=null) {
                println "Account Status:<br/>"
                PermissionReport.printAccountStatus(principal.ldap_account.accountControl)
            }
            
            println "<td>"
            printMembers(report, principal.ldap_account, 0)
            println "</td>"        
        } else {
            println "<td></td><td></td>"
        }
        println "</tr>"
    }
    println "</table>"    
 */     
} else if (p_group_by=="Database") {
 
    println "<h1>Database Permission</h1>"
    println """<table cellspacing="0" class="simple-table" border="1">"""
    println """<tr style="background-color:#EEE">"""
    println "<td>Server</td>"
    println "<td>Database</td>"
    println "<td>Database User</td>"
    println "<td>Server Principal</td>"
    println "<td>Principal Type</td>"
    println "<td>Principal Status</td>" 
    println "<td>Database Permissions</td>"
    println "<td>Account Info</td>"
    println "<td>Members</td>"
    println "</tr>"
    
    p_servers.each { serverName ->
        def databases = result["${serverName}_db"]
        def serverPrincipals = result["${serverName}_principals"]
        
        databases.each { dbName, dbPrincipalList ->
            dbPrincipalList.each { dbUserName, dbPrincipal ->
                print "<tr><td>${serverName}</td><td>${dbName}</td>"
                print "<td>${dbPrincipal.db_principal_name}</td>"
                if (dbPrincipal.server_principal_name == null) {
                    print "<td>ORPHANED</td>"
                } else {
                    print "<td>${dbPrincipal.server_principal_name}</td>"
                }
                
                print "<td>${getNotNull(dbPrincipal.principal_type)}</td>"                
                def srvPrincipal =  serverPrincipals[dbPrincipal.server_principal_name]
                if (srvPrincipal!=null) {
                    print "<td>${srvPrincipal.disabled == null ? "" : (srvPrincipal.disabled ? "disabled" : "enabled" )}</td>"
                } else {
                    print "<td></td>"
                }
                print "<td>${dbPrincipal.db_roles.join("<br/>")}"
                if (dbPrincipal.db_permissions.size()>0) {
                    print "<br/><br/>Permissions: <br/>"
                    print dbPrincipal.db_permissions.join("<br/>")
                }
                print "</td>"

                if (srvPrincipal!=null && srvPrincipal.ldap_account!=null) {
                
                    print """<td>Title: ${srvPrincipal.ldap_account.title}<br/>"""
                    if (srvPrincipal.ldap_account.accountControl!=null) {
                        println "Account Status:<br/>"
                        PermissionReport.printAccountStatus(srvPrincipal.ldap_account.accountControl)
                    }
                    
                    println "<td>"
                    printMembers(report, srvPrincipal.ldap_account, 0)
                    println "</td>"        
                } else {
                    println "<td></td><td></td>"
                }
                println "</tr>"
            }
        }
    }
   
    
    
    println "</table>"
} else {
    logger.error("Unexpected group by parameter value ${p_group_by}")
}
