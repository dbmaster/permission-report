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
println "<td>Account Info</td>"
println "<td>Members</td>"
println "</tr>"

def report =new PermissionReport(dbm, logger)
result = report.getPrincipals(p_servers)

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

def printAccountStatus(status) {
    if (status==null) {
        return
    } else {
        // TODO add descriptions: https://support.microsoft.com/en-us/kb/305144
        def status2 = Long.parseLong(status)
        if ((status2  & 0x0001)> 0 )     { print "Script<br/>" }
        if ((status2  & 0x0002) >0 )     { print "Account disabled<br/>" }
        if ((status2  & 0x0008) >0 )     { print "Homedir required<br/>" }
        if ((status2  & 0x0010) >0 )     { print "Lockout<br/>" }
        if ((status2  & 0x0020) >0 )     { print "Password not required<br/>" }
        if ((status2  & 0x0040) >0 )     { print "Cannot change password<br/>" }
        if ((status2  & 0x0080) >0 )     { print "Ecrypted password allowed<br/>" }
        if ((status2  & 0x1000) >0 )     { print "Temp duplicated account<br/>" }
        if ((status2  & 0x0200) >0 )     { print "Normal Account<br/>" }
        if ((status2  & 0x0800) >0 )     { print "Interdomain trust account<br/>" }
        if ((status2  & 0x1000) >0 )     { print "Workstation trust account<br/>" }
        if ((status2  & 0x2000) >0 )     { print "Server trust account<br/>" }
        if ((status2  & 0x10000) >0 )    { print "Password does not expire<br/>" }
        if ((status2  & 0x20000) >0 )    { print "MNS logon account <br/>" }
        if ((status2  & 0x40000) >0 )    { print "Smartcard required<br/>" }
        if ((status2  & 0x80000) >0 )    { print "Trusted for delegation<br/>" }
        if ((status2  & 0x100000) >0 )   { print "Not delegated<br/>" }
        if ((status2  & 0x200000) >0 )   { print "Use DES key only<br/>" }
        if ((status2  & 0x400000) >0 )   { print "Do not require preauth<br/>" }
        if ((status2  & 0x800000) >0 )   { print "Password expired<br/>" }
        if ((status2  & 0x1000000) >0 )  { print "Trusted to auth for delegation<br/>" }
        if ((status2  & 0x04000000) >0 ) { print "Partial secrets account<br/>" }
    }
}

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
            printAccountStatus(principal.ldap_account.accountControl)
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