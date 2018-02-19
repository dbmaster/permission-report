package io.dbmaster.tools.permission_report;

import java.sql.Timestamp;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

public class DatabasePrincipal implements java.io.Serializable {
    int principal_id;
    
    String db_principal_name;

    String server_principal_name;

    String principal_type;

    Set<String> db_roles       = new HashSet<String>();
    
    Set<String> db_permissions = new HashSet<String>();
}