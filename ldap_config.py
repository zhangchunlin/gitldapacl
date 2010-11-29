#! /usr/bin/env python
#coding=utf-8

#ldap(or active directory) server uri
server_uri='ldap://your_ad_server'

#use this username to login ldap server,to authentication other user
bind_dn='your_dc\your_username'

#password of "bind_dn"
bind_pw='your_password'

#ldap base dn
base_dn='dc=dc1,dc=dc2'