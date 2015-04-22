import java.text.SimpleDateFormat
import java.text.DateFormat
import org.apache.commons.lang.StringEscapeUtils
import org.apache.commons.lang.StringUtils
import com.branegy.service.connection.api.ConnectionService

def spanAttr(String attribute, String value) {
        return "<span style=\"color:#d3d3d3;\">"+attribute+":</span> "+value;
}



def printMembers (report, account, level ) {
    if (account==null || account.members==null) {
        return
    }

    account.members.each { member_dn ->
        def member = report.ldapAccountByDN[member_dn]
        if (member == null) {
            logger.debug("Account for ${member_dn} does not exist")
        } else {
            // TODO move to global level
            
            int disabled_mask = 0x0002
            def disabled = member.disabled!=null && ((Integer.parseInt(member.disabled) & disabled_mask) > 0)
            print  StringUtils.repeat("&nbsp;&nbsp;", level*2)
            print  spanAttr("name", member.title)
            print  " "
            print  spanAttr("sAMAccountName",member.name)
            print  " "
            print  spanAttr("disabled", disabled ? "disabled" : "enabled")
            println "<br/>"
            printMembers(report, member, level+1)
        }
    }
}

def report =new PermissionReport(dbm, logger)
def connectionSrv = dbm.getService(ConnectionService.class)
report.loadLdapAccounts(connectionSrv)

p_groups.split("\\r?\\n").each { accountName ->
    def account  = report.ldapAccountByName[accountName.trim()]
    if (account == null) {
        println "<p> Account ${accountName} not found</p>"
    } else {
        println "<p>Members for account ${accountName}</p>"
        printMembers(report, account, 0)
    }
}