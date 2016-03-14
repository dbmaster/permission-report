import groovy.json.StringEscapeUtils
import groovy.sql.Sql

import io.dbmaster.tools.permission_report.*

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Statement
import java.util.concurrent.CancellationException

import org.slf4j.Logger

import com.branegy.dbmaster.connection.ConnectionProvider
import com.branegy.dbmaster.connection.JdbcConnector
import com.branegy.dbmaster.custom.CustomFieldConfig
import com.branegy.dbmaster.custom.CustomObjectEntity
import com.branegy.dbmaster.custom.CustomObjectService
import com.branegy.dbmaster.custom.CustomObjectTypeEntity
import com.branegy.dbmaster.custom.CustomFieldConfig.Type
import com.branegy.dbmaster.custom.field.server.api.ICustomFieldService
import com.branegy.dbmaster.model.*
import com.branegy.dbmaster.util.NameMap
import com.branegy.scripting.DbMaster
import com.branegy.service.connection.api.ConnectionService
import com.branegy.service.core.QueryRequest

import io.dbmaster.tools.LdapSearch
import io.dbmaster.tools.LdapUserCache

public class PermissionReport { 
    
    private DbMaster dbm
    private Logger logger
    java.sql.Timestamp processTime = new java.sql.Timestamp(new Date().getTime())
    
    public LdapUserCache ldap

    public PermissionReport(DbMaster dbm, Logger logger) {
        this.dbm = dbm
        this.logger = logger
        this.ldap = new LdapUserCache(dbm, logger)
    }
     
    private Map getDatabasePermissions(connection, serverPrincipals) {
        Map result = [:]
        
        def sql = new Sql(connection)
        
        // All ONLINE DBs
        def query = "select name from sys.databases where state=0 order by name" 
        def dbs = sql.rows(query).collect { it.name }
        dbs.each { dbName ->
            def dbPrincipals = [:]
            query = """USE [${dbName}];                     
                     SELECT dp.principal_id,
                            dp.name,
                            dp.type,
                            dp.type_desc,
                            SUSER_SNAME(dp.sid) as server_name
                     FROM sys.database_principals dp  
                     -- left join sys.server_principals sp on dp.sid=sp.sid
                     WHERE dp.type<>'R' -- role
                       AND dp.name NOT IN ('guest','INFORMATION_SCHEMA','sys','MS_DataCollectorInternalUser')"""
            
            logger.debug("Executing "+query)    
            
            sql.eachRow(query.toString()) { row ->
                def principal = new DatabasePrincipal()
                principal.principal_id = row.principal_id
                principal.db_principal_name = row.name
                principal.server_principal_name = row.server_name
                principal.principal_type = row.type_desc
                
                dbPrincipals [ row.name ] = principal
            }
            result[dbName] = dbPrincipals
            
            query = """WITH role_members AS (
                        SELECT rp.name root_role, 
                               rm.role_principal_id, 
                               rp.name, 
                               rm.member_principal_id,
                               mp.name as member_name, 
                               mp.sid, 
                               1 as depth  
                        FROM sys.database_role_members rm
                        INNER JOIN sys.database_principals rp on rp.principal_id = rm.role_principal_id
                        INNER JOIN sys.database_principals mp on mp.principal_id = rm.member_principal_id

                        UNION ALL

                        SELECT cte.root_role, 
                               cte.member_principal_id, 
                               cte.member_name, 
                               rm.member_principal_id,
                               mp.name as member_name, 
                               mp.sid, 
                               cte.depth +1
                        FROM sys.database_role_members rm
                        INNER JOIN sys.database_principals mp on mp.principal_id = rm.member_principal_id
                        INNER JOIN role_members cte on cte.member_principal_id = rm.role_principal_id
                       )				
                       SELECT DISTINCT member_name, root_role as role_name from role_members rm"""
            
            sql.eachRow(query.toString()) { row ->
                def principal = dbPrincipals[row.member_name]
                if (principal==null) {
                    logger.warn("Principal for name ${row.member_name} not found")
                } else {
                    principal.db_roles.add(row.role_name)
                }
            }
            
            query = """
            
               SELECT CASE WHEN P.state_desc = 'GRANT_WITH_GRANT_OPTION' 
                      THEN 'GRANT' 
                      ELSE P.state_desc END AS cmd_state,
                      P.permission_name,
               'ON '+ CASE P.class_desc
                   WHEN 'DATABASE' THEN 'DATABASE::'+QUOTENAME(DB_NAME())
                   WHEN 'SCHEMA' THEN 'SCHEMA::'+QUOTENAME(S.name)
                   WHEN 'OBJECT_OR_COLUMN' THEN 'OBJECT::'+QUOTENAME(OS.name)+'.'+QUOTENAME(O.name)+
                     CASE WHEN P.minor_id <> 0 THEN '('+QUOTENAME(C.name)+')' ELSE '' END
                   WHEN 'DATABASE_PRINCIPAL' THEN
                     CASE PR.type_desc 
                       WHEN 'SQL_USER' THEN 'USER'
                       WHEN 'DATABASE_ROLE' THEN 'ROLE'
                       WHEN 'APPLICATION_ROLE' THEN 'APPLICATION ROLE'
                     END +'::'+QUOTENAME(PR.name)
                   WHEN 'ASSEMBLY' THEN 'ASSEMBLY::'+QUOTENAME(A.name)
                   WHEN 'TYPE' THEN 'TYPE::'+QUOTENAME(TS.name)+'.'+QUOTENAME(T.name)
                   WHEN 'XML_SCHEMA_COLLECTION' THEN 'XML SCHEMA COLLECTION::'+QUOTENAME(XSS.name)+'.'+QUOTENAME(XSC.name)
                   WHEN 'SERVICE_CONTRACT' THEN 'CONTRACT::'+QUOTENAME(SC.name)
                   WHEN 'MESSAGE_TYPE' THEN 'MESSAGE TYPE::'+QUOTENAME(SMT.name)
                   WHEN 'REMOTE_SERVICE_BINDING' THEN 'REMOTE SERVICE BINDING::'+QUOTENAME(RSB.name)
                   WHEN 'ROUTE' THEN 'ROUTE::'+QUOTENAME(R.name)
                   WHEN 'SERVICE' THEN 'SERVICE::'+QUOTENAME(SBS.name)
                   WHEN 'FULLTEXT_CATALOG' THEN 'FULLTEXT CATALOG::'+QUOTENAME(FC.name)
                   WHEN 'FULLTEXT_STOPLIST' THEN 'FULLTEXT STOPLIST::'+QUOTENAME(FS.name)
                   WHEN 'SEARCH_PROPERTY_LIST' THEN 'SEARCH PROPERTY LIST::'+QUOTENAME(RSPL.name)
                   WHEN 'SYMMETRIC_KEYS' THEN 'SYMMETRIC KEY::'+QUOTENAME(SK.name)
                   WHEN 'CERTIFICATE' THEN 'CERTIFICATE::'+QUOTENAME(CER.name)
                   WHEN 'ASYMMETRIC_KEY' THEN 'ASYMMETRIC KEY::'+QUOTENAME(AK.name)
                 END COLLATE Latin1_General_100_BIN AS securable,
                 DP.name AS grantee,
                 DP.principal_id grantee_id,
                 CASE WHEN P.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN 'WITH GRANT OPTION' ELSE '' END AS grant_option,
                 'AS '+QUOTENAME(G.name) AS grantor
                  FROM sys.database_permissions AS P
                  LEFT JOIN sys.schemas AS S ON P.major_id = S.schema_id
                  LEFT JOIN sys.all_objects AS O
                       JOIN sys.schemas AS OS ON O.schema_id = OS.schema_id
                    ON P.major_id = O.object_id
                  LEFT JOIN sys.types AS T
                       JOIN sys.schemas AS TS ON T.schema_id = TS.schema_id
                    ON P.major_id = T.user_type_id
                  LEFT JOIN sys.xml_schema_collections AS XSC
                       JOIN sys.schemas AS XSS ON XSC.schema_id = XSS.schema_id
                    ON P.major_id = XSC.xml_collection_id
                  LEFT JOIN sys.columns AS C ON O.object_id = C.object_id AND P.minor_id = C.column_id
                  LEFT JOIN sys.database_principals AS PR ON P.major_id = PR.principal_id
                  LEFT JOIN sys.assemblies AS A ON P.major_id = A.assembly_id
                  LEFT JOIN sys.service_contracts AS SC ON P.major_id = SC.service_contract_id
                  LEFT JOIN sys.service_message_types AS SMT ON P.major_id = SMT.message_type_id
                  LEFT JOIN sys.remote_service_bindings AS RSB ON P.major_id = RSB.remote_service_binding_id
                  LEFT JOIN sys.services AS SBS ON P.major_id = SBS.service_id
                  LEFT JOIN sys.routes AS R ON P.major_id = R.route_id
                  LEFT JOIN sys.fulltext_catalogs AS FC ON P.major_id = FC.fulltext_catalog_id
                  LEFT JOIN sys.fulltext_stoplists AS FS ON P.major_id = FS.stoplist_id
                  LEFT JOIN sys.registered_search_property_lists AS RSPL ON P.major_id = RSPL.property_list_id
                  LEFT JOIN sys.asymmetric_keys AS AK ON P.major_id = AK.asymmetric_key_id
                  LEFT JOIN sys.certificates AS CER ON P.major_id = CER.certificate_id
                  LEFT JOIN sys.symmetric_keys AS SK ON P.major_id = SK.symmetric_key_id
                  JOIN sys.database_principals AS DP ON P.grantee_principal_id = DP.principal_id
                  JOIN sys.database_principals AS G ON P.grantor_principal_id = G.principal_id
                where   p.permission_name<>'CONNECT' and DP.name <>'public'"""

            sql.eachRow(query.toString()) { row ->
                def principal = dbPrincipals[row.grantee]
                if (principal==null) {
                    logger.warn("Principal for name ${row.grantee} not found (permission)")
                } else {
                    def text = "${row.cmd_state} ${row.permission_name} ${row.securable} ${row.grant_option}"
                    principal.db_permissions.add(text)
                }
            }

            
        }
        return result
    }
    
    // returns server principals and their server roles (recursevely)
    private Map<String, ServerPrincipal> getServerPrincipals(connection) {
        def serverPrincipals = [:]
        
        logger.info("Getting server principal list")
                
        new Sql(connection).eachRow("""SELECT principal_id, name, type_desc, is_disabled
                                       FROM sys.server_principals 
                                       WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP')
                                       ORDER BY name""")
        { row ->
            def principal = new ServerPrincipal()
            
            logger.info("User ${row.name} is disabled: ${row.is_disabled}")
            
            principal.principal_name     = row.name
            if (row.is_disabled instanceof Boolean) {
                principal.disabled = row.is_disabled
            } else {
                principal.disabled = new Boolean(1 == row.is_disabled)
            }
            principal.principal_type     = row.type_desc
            principal.principal_id       = row.principal_id
            
            // result << principal
            serverPrincipals[principal.principal_name] = principal
            
            if (principal.principal_type.equals("WINDOWS_GROUP") ||
                principal.principal_type.equals("WINDOWS_LOGIN"))
            {
                def parts = principal.principal_name.split("\\\\", 2)
                if (parts.length==2) {
                    def domain = parts[0]
                    def username = parts[1]
                    logger.debug("Domain=${domain} user=${username}")
                    
                    // NT AUTHORITY
                    // NT SERVICE
                    
                    def ldap_account = ldap.ldapAccountByName[principal.principal_name]
                    if (ldap_account==null) {
                        logger.debug("Principal name '${principal.principal_name}' not found");
                    }
                    principal.ldap_account = ldap_account
                }
            }
        }
        
        // Include Roles
        def query = """
            WITH role_members AS (
                SELECT rp.name root_role, 
                       rm.role_principal_id, 
                       rp.name, 
                       rm.member_principal_id,
                       mp.name as member_name, 
                       mp.sid, 
                       1 as depth  
                FROM sys.server_role_members rm
                INNER JOIN sys.server_principals rp on rp.principal_id = rm.role_principal_id
                INNER JOIN sys.server_principals mp on mp.principal_id = rm.member_principal_id

                UNION ALL

                SELECT cte.root_role, 
                       cte.member_principal_id,
                       cte.member_name, 
                       rm.member_principal_id,
                       mp.name as member_name, 
                       mp.sid, 
                       cte.depth +1
                FROM sys.server_role_members rm
                INNER JOIN sys.server_principals mp on mp.principal_id = rm.member_principal_id
                INNER JOIN role_members cte on cte.member_principal_id = rm.role_principal_id
            )
            SELECT distinct member_principal_id, member_name, root_role FROM role_members"""
            
        new Sql(connection).eachRow(query) { row ->
            def principal = serverPrincipals[row.member_name]
            if (principal==null) {
                logger.warn("Server principal with name ${row.member_name} not found")
            } else {
                principal.server_roles.add(row.root_role)
            }
        }
        
        return serverPrincipals
    }
    
    public Map getPrincipals(String[] servers) {
        // Map<String connection, Map<String principal : Principal Info>>
        // Map<String connection, Map<String database  : 
        def result = [:]

        def connectionSrv = dbm.getService(ConnectionService.class)
        
        ldap.loadLdapAccounts(connectionSrv)
        
        def dbConnections
        if (servers!=null && servers.size()>0) {
            dbConnections = servers.collect { serverName -> connectionSrv.findByName(serverName) }
        } else {
            dbConnections = connectionSrv.getConnectionList()
        }


        dbConnections.each { connectionInfo ->
            try {
                def serverName = connectionInfo.getName()
                def connector = ConnectionProvider.getConnector(connectionInfo)
                if (!(connector instanceof JdbcConnector)) {
                    logger.info("Skipping checks for connection ${serverName} as it is not a database one")
                    return
                } else {
                    logger.info("Connecting to ${serverName}")
                }

                Connection connection = connector.getJdbcConnection(null)
                dbm.closeResourceOnExit(connection)
            
                // principal list (sql users, windows users, windows groups)
                def principals = getServerPrincipals(connection)
                result["${serverName}_principals"]  = principals

                result["${serverName}_db"]  = getDatabasePermissions(connection, principals)

                // if (Thread.interrupted()) {
                //    throw new CancellationException();
                // }
                connection.close()
            } catch (CancellationException e) {
                throw e;
            } catch (Exception e) {
                def msg = "Error occurred "+e.getMessage()
                org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e)
                logger.error(msg, e)
            }
        }
        return result
    }
    
    // TODO: convert result to a set of Strings
    public static void printAccountStatus(status) {
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
}