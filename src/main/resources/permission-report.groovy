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

def printAccountStatus(status) {
    if (status==null) {
        return
    } else {
        // TODO add descriptions: https://support.microsoft.com/en-us/kb/305144
        def status2 = Long.parseLong(status)
        if ((status2  & 0x0001)> 0 ) { print "SCRIPT<br/>" }
        if ((status2  & 0x0002) >0 ) { print "ACCOUNTDISABLE<br/>" }
        if ((status2  & 0x0008) >0 ) { print "HOMEDIR_REQUIRED<br/>" }
        if ((status2  & 0x0010) >0 ) { print "LOCKOUT<br/>" }
        if ((status2  & 0x0020) >0 ) { print "PASSWD_NOTREQD<br/>" }
        if ((status2  & 0x0040) >0 ) { print "PASSWD_CANT_CHANGE<br/>" }
        if ((status2  & 0x0080) >0 ) { print "ENCRYPTED_TEXT_PWD_ALLOWED<br/>" }
        if ((status2  & 0x1000) >0 ) { print "TEMP_DUPLICATE_ACCOUNT<br/>" }
        if ((status2  & 0x0200) >0 ) { print "NORMAL_ACCOUNT<br/>" }
        if ((status2  & 0x0800) >0 ) { print "INTERDOMAIN_TRUST_ACCOUNT<br/>" }
        if ((status2  & 0x1000) >0 ) { print "WORKSTATION_TRUST_ACCOUNT<br/>" }
        if ((status2  & 0x2000) >0 ) { print "SERVER_TRUST_ACCOUNT<br/>" }
        if ((status2  & 0x10000) >0 ) { print "DONT_EXPIRE_PASSWORD<br/>" }
        if ((status2  & 0x20000) >0 ) { print "MNS_LOGON_ACCOUNT<br/>" }
        if ((status2  & 0x40000) >0 ) { print "SMARTCARD_REQUIRED<br/>" }
        if ((status2  & 0x80000) >0 ) { print "TRUSTED_FOR_DELEGATION<br/>" }
        if ((status2  & 0x100000) >0 ) { print "NOT_DELEGATED<br/>" }
        if ((status2  & 0x200000) >0 ) { print "USE_DES_KEY_ONLY<br/>" }
        if ((status2  & 0x400000) >0 ) { print "DONT_REQ_PREAUTH<br/>" }
        if ((status2  & 0x800000) >0 ) { print "PASSWORD_EXPIRED<br/>" }
        if ((status2  & 0x1000000) >0 ) { print "TRUSTED_TO_AUTH_FOR_DELEGATION<br/>" }
        if ((status2  & 0x04000000) >0 ) { print "PARTIAL_SECRETS_ACCOUNT<br/>" }
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
        if (principal.ldap_account.disabled!=null) {
            println "Account Status:<br/>"
            printAccountStatus(principal.ldap_account.disabled)
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