import groovy.json.StringEscapeUtils
import groovy.sql.Sql
import io.dbmaster.tools.login.audit.*

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Statement
import java.util.concurrent.CancellationException
import java.util.regex.Matcher
import java.util.regex.Pattern

import io.dbmaster.tools.ldap.LdapSearch

import javax.naming.*
import javax.naming.directory.*
import javax.naming.ldap.*

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
import io.dbmaster.tools.ldap.LdapUserCache

public class PermissionReport { 
    
    private DbMaster dbm
    private Logger logger
    public  Date since
    java.sql.Timestamp processTime = new java.sql.Timestamp(new Date().getTime())
    
    public LdapUserCache ldap

    public PermissionReport(DbMaster dbm, Logger logger) {
        this.dbm = dbm
        this.logger = logger
        this.ldap = new LdapUserCache(dbm, logger)
    }
     
    private void setDatabaseRoles(connection, serverPrincipals) {
        def sql = new Sql(connection)
        sql.execute("""create table #tempschema 
                       (principal_id int, 
                        database_name sysname,
                        role_name sysname,
                        principal_name sysname)""")

        def query = """
            INSERT INTO #tempschema
                EXEC sp_MSForEachDB '
                USE [?];
                WITH role_members AS (

                SELECT rp.name root_role, 
                       rm.role_principal_id, 
                       rp.name, 
                       rm.member_principal_id,
                       mp.name as member_name, 
                       mp.sid, 
                       1 as depth  
                FROM sys.database_role_members rm
                 inner join sys.database_principals rp on rp.principal_id = rm.role_principal_id
                 inner join sys.database_principals mp on mp.principal_id = rm.member_principal_id

                UNION ALL

                SELECT cte.root_role, cte.member_principal_id, cte.member_name, rm.member_principal_id,mp.name as member_name, mp.sid, cte.depth +1
                FROM sys.database_role_members rm
                 inner join sys.database_principals mp on mp.principal_id = rm.member_principal_id
                 inner join role_members cte on cte.member_principal_id = rm.role_principal_id
                )
                SELECT distinct sp.principal_id, ''?'' as database_name, root_role as role_name, sp.name from role_members rm
                inner join sys.server_principals sp on rm.sid=sp.sid 
                '
        """

        sql.execute(query)

        sql.eachRow("select distinct * from #tempschema") { row ->
            def principal = serverPrincipals[row.principal_id]
            if (principal==null) {
                logger.warn("Principal for id ${row.principal_id} not found")
            } else {
                principal.db_roles.add(["db" : row.database_name, "role" : row.role_name])
            }
        }
        sql.execute("drop table #tempschema")                
    }
    
    private void setServerRoles(connection, serverPrincipals) {
        def query = """
            WITH role_members AS (
              SELECT rp.name root_role, rm.role_principal_id, rp.name, rm.member_principal_id,mp.name as member_name, mp.sid, 1 as depth  
              FROM sys.server_role_members rm
              INNER JOIN sys.server_principals rp on rp.principal_id = rm.role_principal_id
              INNER JOIN sys.server_principals mp on mp.principal_id = rm.member_principal_id

              UNION ALL

              SELECT cte.root_role, cte.member_principal_id, cte.member_name, rm.member_principal_id,mp.name as member_name, mp.sid, cte.depth +1
              FROM sys.server_role_members rm
              INNER JOIN sys.server_principals mp on mp.principal_id = rm.member_principal_id
              INNER JOIN role_members cte on cte.member_principal_id = rm.role_principal_id
            )
            SELECT distinct member_principal_id, member_name, root_role FROM role_members"""
            
        new Sql(connection).eachRow(query) { row ->
            def principal = serverPrincipals[row.member_principal_id]
            if (principal==null) {
                logger.warn("Principal for id ${row.member_principal_id} not found")
            } else {
                principal.server_roles.add(row.root_role)
            }
        }
    }
    
    public List<PrincipalInfo> getPrincipals(String[] servers) {
        List<PrincipalInfo> result = []

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
                def serverPrincipals = [:]            
                def connector = ConnectionProvider.getConnector(connectionInfo)
                if (!(connector instanceof JdbcConnector)) {
                    logger.info("Skipping checks for connection ${serverName} as it is not a database one")
                    return
                } else {
                    logger.info("Connecting to ${serverName}")
                }

                Connection connection = connector.getJdbcConnection(null)
                dbm.closeResourceOnExit(connection)
            
                // login list
                logger.info("Getting server principal list")
                
                new Sql(connection).eachRow("""SELECT principal_id, name, type_desc, is_disabled
                                               FROM sys.server_principals 
                                               WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP')
                                               ORDER BY name""")
                    { row ->
                        def principal = new PrincipalInfo()
                        
                        principal.connection_name    = serverName
                        principal.principal_name     = row.name
                        principal.disabled           = new Boolean(1 == row.is_disabled)
                        principal.principal_type     = row.type_desc
                        principal.principal_id       = row.principal_id
                        
                        result << principal
                        serverPrincipals[row.principal_id] = principal
                        
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
                                principal.ldap_account = ldap_account
                            }
                        }
                    }

                setServerRoles(connection, serverPrincipals)
                setDatabaseRoles(connection, serverPrincipals)
                    //if (Thread.interrupted()) {
                    //    throw new CancellationException();
                    //}
                connection.close()
                
                // calculate 
          
                        
            } catch (CancellationException e) {
                throw e;
            } catch (Exception e) {
                def msg = "Error occurred "+e.getMessage()
                org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e)
                logger.error(msg, e)
            }
        }
        result.sort { a, b -> a.connection_name.compareToIgnoreCase(b.connection_name)*10000+
                              a.principal_name.compareToIgnoreCase(b.principal_name) }

        return result
    }
}