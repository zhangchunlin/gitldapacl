#! /usr/bin/env python
#coding=utf-8

#-----USER CONFIG PART BEGIN

#modify GIT_AUTH_DIR_PATH to your path for holding gitauth_wsgi.py
GIT_AUTH_DIR_PATH = "D:/Service/gitauth"
#modify to your acl file path
GIT_ACL_INI_FILE_PATH = "D:/Service/gitauth/gitacl.ini"

#-----USER CONFIG PART END

import urlparse

import sys; sys.path.insert(0, GIT_AUTH_DIR_PATH)

import ldap_config,ldap_login

def __init_ldap():
  if not globals().has_key('__authen_ldap_authenticator'):
    global __authen_ldap_authenticator
    #apache.log_error("server:%s,bind_dn:%s,bind_pw:%s,base_dn:%s"%(ldap_config.server_uri,ldap_config.bind_dn,ldap_config.bind_pw,ldap_config.base_dn))
    __authen_ldap_authenticator = ldap_login.LDAPAuth(
        # the values shown below are the DEFAULT values (you may remove them if you are happy with them),
        # the examples shown in the comments are typical for Active Directory (AD) or OpenLDAP.
        server_uri= ldap_config.server_uri,  # ldap / active directory server URI
                                        # use ldaps://server:636 url for ldaps,
                                        # use  ldap://server for ldap without tls (and set start_tls to 0),
                                        # use  ldap://server for ldap with tls (and set start_tls to 1 or 2).
        bind_dn= ldap_config.bind_dn,  # We can either use some fixed user and password for binding to LDAP.
                     # Be careful if you need a % char in those strings - as they are used as
                     # a format string, you have to write %% to get a single % in the end.
                     #bind_dn = 'binduser@example.org' # (AD)
                     #bind_dn = 'cn=admin,dc=example,dc=org' # (OpenLDAP)
                     #bind_pw = 'secret'
                     # or we can use the username and password we got from the user:
                     #bind_dn = '%(username)s@example.org' # DN we use for first bind (AD)
                     #bind_pw = '%(password)s' # password we use for first bind
                     # or we can bind anonymously (if that is supported by your directory).
                     # In any case, bind_dn and bind_pw must be defined.
        bind_pw= ldap_config.bind_pw,
        base_dn= ldap_config.base_dn,  # base DN we use for searching
                     #base_dn = 'ou=SOMEUNIT,dc=example,dc=org'
        scope=2, # scope of the search we do (2 == ldap.SCOPE_SUBTREE)
        referrals=0, # LDAP REFERRALS (0 needed for AD)
        search_filter='(sAMAccountName=%(username)s)',  # ldap filter used for searching:
                                             #search_filter = '(sAMAccountName=%(username)s)' # (AD)
                                             #search_filter = '(uid=%(username)s)' # (OpenLDAP)
                                             # you can also do more complex filtering like:
                                             # "(&(cn=%(username)s)(memberOf=CN=WikiUsers,OU=Groups,DC=example,DC=org))"
        # some attribute names we use to extract information from LDAP (if not None,
        # if None, the attribute won't be extracted from LDAP):
        givenname_attribute=None, # often 'givenName' - ldap attribute we get the first name from
        surname_attribute=None, # often 'sn' - ldap attribute we get the family name from
        aliasname_attribute=None, # often 'displayName' - ldap attribute we get the aliasname from
        email_attribute=None, # often 'mail' - ldap attribute we get the email address from
        email_callback=None, # callback function called to make up email address
        coding='utf-8', # coding used for ldap queries and result values
        timeout=10, # how long we wait for the ldap server [s]
        start_tls=0, # usage of Transport Layer Security 0 = No, 1 = Try, 2 = Required
        tls_cacertdir='',
        tls_cacertfile='',
        tls_certfile='',
        tls_keyfile='',
        tls_require_cert=0, # 0 == ldap.OPT_X_TLS_NEVER (needed for self-signed certs)
        bind_once=False, # set to True to only do one bind - useful if configured to bind as the user on the first attempt
    )

def ini2acl_dict(fp):
    import dict4ini
    ini = dict4ini.DictIni(fp)
    acldict = {}
    groups = ini.groups
    for config_name, value in ini.ordereditems(ini):
        if config_name[-1:]==":":
            repo_name = config_name[:-1]
            #print value
            for role in value:
                #print role,value[role]
                if role[0]=="@":
                    groupname = role[1:]
                    #print(groupname)
                    if groups.has_key(groupname):
                        for user in groups[groupname]:
                            #print("%s has:%s"%(role,user))
                            if not acldict.has_key(repo_name):
                                acldict[repo_name] = {}
                            acldict[repo_name][user]=value[role]
                else:
                    if not acldict.has_key(repo_name):
                        acldict[repo_name] = {}
                    acldict[repo_name][role]=value[role]
                    
    return acldict,ini

def __init_acl():
    #if not globals().has_key('__acldict'):
    global __acldict,__configini
    __acldict,__configini = ini2acl_dict(GIT_ACL_INI_FILE_PATH)

def uri_can_access_by_user(uri,user):
    uri_prefix = __configini.common.uri_prefix
    uri_prefix_len = len(uri_prefix)
    
    uri_prefix_gitweb = __configini.common.uri_prefix_gitweb
    uri_prefix_gitweb_len = len(uri_prefix_gitweb)
    
    if uri[0:uri_prefix_len]==uri_prefix:#git case
        uri_strip = uri[uri_prefix_len:]
        repo_name = uri_strip.split("/")[0]
        need_write_access = (uri_strip.find("git-receive-pack")!=-1)
    elif uri[0:uri_prefix_gitweb_len]==uri_prefix_gitweb:#gitweb case
        uresult = urlparse.urlparse(uri)
        qresult = urlparse.parse_qs(uresult.query)
        if qresult.has_key("p"):#gitweb project case
            repo_name = qresult["p"][0]
            need_write_access = False
        else:#index page case
            return True
    else:
        return False #Can not recognize the url
    
    #print __acldict,__configini
    #print(repo_name,user,uri,__acldict)
    if need_write_access:
        #need w
        try:
            have_w_permission = __acldict[repo_name][user].find("w")!=-1
            if not have_w_permission:
                print("%s have not write permission with %s"%(user,uri))
            return have_w_permission
        except KeyError,e:
            print("%s have not set write permission with %s"%(user,uri))
            return False
    else:
        #need r
        try:
            have_r_permission =  __acldict[repo_name][user].find("r")!=-1
            if not have_r_permission:
                print("%s have not read permission with %s"%(user,uri))
            return have_r_permission
        except KeyError,e:
            print("%s have not set read permission with %s"%(user,uri))
            return False
        
    #print repo_name,__acldict[repo_name]
    print("should not be here!")
    return False


def check_password(environ, user, password):
    #print(environ)
    __init_ldap()
    __init_acl()
    if __authen_ldap_authenticator.login(user,password):
        return uri_can_access_by_user(environ['REQUEST_URI'],user)
    return False

