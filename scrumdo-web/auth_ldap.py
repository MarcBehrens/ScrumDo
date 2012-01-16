#AUTH_LDAP_HOST = 'ldaps://localhost'
#AUTH_LDAP_GROUPS = ('grup')
#AUTH_LDAP_BINDDN = "cn=admin,dc=alvinsay,dc=tw"
#AUTH_LDAP_BINDPW = "an"
#AUTH_LDAP_BASEDN_USER = 'ou=user,ou=login,dc=example,dc=com'
#AUTH_LDAP_BASEDN_GROUP = 'ou=group,ou=login,dc=example,dc=com'
#AUTH_LDAP_CREATE_STAFF = True
#AUTHENTICATION_BACKENDS = ('myproject.auth_ldap.LdapAuthBackend',)
#AUTHENTICATION_BACKENDS = ('myproject.auth_ldap.LdapAuthBackend',
#                           'django.contrib.auth.backends.ModelBackend')

from django.contrib.auth.models import User, Group
from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from emailconfirmation.models import EmailAddress

import ldap


def ldap_get_dn(username):
    dn = "uid=" + username +"," + settings.AUTH_LDAP_BASEDN_USER
    return dn

def ldap_authenticate( l, dn , password ):
    try:
        l.simple_bind_s( dn, password )
        return True
    except:
        return False

def ldap_get_attrs(l, dn, attrs ):
    try:
        return l.search_s( dn, ldap.SCOPE_BASE, '(objectclass=person)',attrs)[0][1]
    except:
        return None


class LdapAuthBackend(ModelBackend):
    def authenticate(self, username=None, password=None):

        username = username.lower() 
        # Authenticate against ldap
        l = ldap.initialize(getattr( settings, "AUTH_LDAP_HOST", "ldap://localhost"))

        dn = ldap_get_dn( username )
        if not ldap_authenticate( l, dn, password ):
            return None

        # OK, we've authenticated. Do we exist?
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            attrs = ldap_get_attrs(l, dn, ['sn', 'givenName', 'mail'])
            user = User.objects.create_user(username, '', password)
            user.is_active = True
            user.first_name = attrs.get('givenName', [''])[0]
	    user.last_name = attrs.get('sn', [''])[0]
	    user.email = attrs.get('mail', [''])[0]
	    user.save()
            # EmailAddress.objects.add_email(user, user.email)
       
        l.unbind_s()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

