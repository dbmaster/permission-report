package io.dbmaster.tools.permission_report;

import java.sql.Timestamp;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

public class ServerPrincipal implements java.io.Serializable {
    int principal_id;

    String sid;
    
    String principal_name;

    String principal_type;

    // NULL means we don't know
    Boolean disabled;

    Set<String> server_roles = new HashSet<String>();

    Object ldap_account;
}