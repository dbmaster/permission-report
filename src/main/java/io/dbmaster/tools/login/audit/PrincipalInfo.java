package io.dbmaster.tools.login.audit;

import java.sql.Timestamp;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

public class PrincipalInfo implements java.io.Serializable {
        int principal_id;
        String connection_name;
        String principal_name;
        String principal_type;
        // NULL means we don't know
        Boolean disabled;
        Set<String> server_roles = new HashSet<String>();
        Set db_roles = new HashSet();
        Object ldap_account;
        
        Set<String> linked_accounts;
        
        public synchronized void linkAccount(String account) {
            if (linked_accounts==null) {
                linked_accounts = new HashSet<String>();
            }
            linked_accounts.add(account);
        }
}