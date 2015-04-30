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

println """<table cellspacing='0' class='simple-table' border='1'>"""
println """<tr style="background-color:#EEE">"""
println "<td>Server</td>"
println "<td>Principal</td>"
println "<td>Principal Status</td>"
println "<td>Type</td>"
println "<td>Server Roles</td>"
println "<td>Database Permissions</td>"
println "<td>LDAP Info</td>"
println "<td>SubGroups</td>"
println "</tr>"

def report =new PermissionReport(dbm, logger)
result = report.getPrincipals(p_servers)

def printAttr(String attribute, String value) {
        return "<span style=\"color:#d3d3d3;\">"+attribute+":</span> "+value;
}
  
def printMembers (report, account, level ) {
    if (account==null || account.members==null) {
        return
    }

    account.members.each { member_dn ->
        def member = report.ldap.ldapAccountByDN[member_dn]
        if (member == null) {
            logger.debug("Account for ${member_dn} does not exist")
        } else {
            println  StringUtils.repeat("&nbsp;&nbsp;", level*2) +
                     printAttr("name", member.title)+" " + printAttr("sAMAccountName",member.name)+"<br/>";
            printMembers(report, member, level+1)
        }
    }
}

result.each { principal ->
    println "<tr valign=\"top\">"
    println "<td>${principal.connection_name}</td>"    
    print "<td>${principal.principal_name}</td>"
    println "<td>${principal.disabled == null ? "" : (principal.disabled ? "disabled" : "enabled" )}</td>"
    println "<td>${getNotNull(principal.principal_type)}</td>"
    println "<td>${principal.server_roles.join("<br/>")}</td>"
    println "<td>${principal.db_roles.collect { it.db+":"+it.role }.join("<br/>")}</td>"
    if (principal.ldap_account!=null) {
        println """<td>Title: ${principal.ldap_account.title}<br/>
                       Disabled: ${principal.ldap_account.disabled}
                </td>"""
                
        println "<td>"
        printMembers(report, principal.ldap_account, 0)
        println "</td>"        
    } else {
        println "<td></td><td></td>"
    }

    println "</tr>"
}
println "</table>"