'''A CKAN plugin that enables SSO using a simple header parameter.

'''
import uuid
from ckantoolkit import config
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging

class SimpleSSOPlugin(plugins.SingletonPlugin):
    '''A CKAN plugin that enables SSO using a simple header parameter.

    '''
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        '''Update CKAN's config with settings needed by this plugin.

        '''
        toolkit.add_template_directory(config, 'templates')
        self.header_parameter = config.get('ckan.simplesso.header_parameter', 'partyID')
        self.header_username = config.get('ckan.simplesso.header_username', 'username')
        self.header_email = config.get('ckan.simplesso.header_email', 'email')
        self.email_domain = config.get('ckan.simplesso.email_domain')

    def login(self):
        pass

    def identify(self):
        '''Identify which user (if any) is logged in via simple SSO header.

        If a logged in user is found, set toolkit.c.user to be their user name.

        '''
        logger = logging.getLogger(__name__)
        logger.debug('ESAS: HEADER SENT TO CKAN')
        logger.debug(self.header_parameter)
        logger.debug(toolkit.request.headers)
        if self.header_parameter in toolkit.request.headers:
            logger.debug('PartyID')
            logger.debug(toolkit.request.headers.get('partyID'))
            userid = toolkit.request.headers.get(self.header_parameter).lower()
            username = toolkit.request.headers.get(self.header_username).lower()
            email = toolkit.request.headers.get(self.header_email).lower()
            user = get_user_by_userid(userid)

            if user:
                # Check if ESAS email for user has changed.
                # If it has changed then update user email to match
                # CKAN is not system of record for email. 
                # Changes as needed to match ESAS header.
                if email != user['email']:
                    logger.log('ESAS: A user account has changed email.')
                    user=toolkit.get_action('user_update')(
                        context={'ignore_auth': True},
                        data_dict={'id':userid,
                                   'email': email})
            if not user:
                # Check if user email is already associated with an existing account.
                # If there are duplicate emails raise error
                email_check = get_user_by_email(email)
                if email_check:
                    logger.error('ESAS: An existing account already has this email')  
                # A user with this username doesn't yet exist in CKAN
                # - so create one.
                logger.log('ESAS: user not found. Creating new CKAN user.')
                user = toolkit.get_action('user_create')(
                    context={'ignore_auth': True},
                    data_dict={'email': email,
                               'id': userid,
                               'name': username,
                               'password': generate_password()})
            toolkit.c.user = user['name']

    def logout(self):
        pass

    def abort(self, status_code, detail, headers, comment):
        pass


def get_user_by_username(username):
    '''Return the CKAN user with the given username.

    :rtype: A CKAN user dict

    '''
    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    import ckan.model
    user = ckan.model.User.get(username)

    if user:
        user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
        return user_dict
    else:
        return None

def get_user_by_userid(userid):
    '''Return the CKAN user with the given userid.

    :rtype: A CKAN user dict

    '''
    user = ckan.model.User.get(userid)

    if user:
        user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
        return user_dict
    else:
        return None

def get_user_by_email(email):
    '''Return the CKAN user with the given email address.

    :rtype: A CKAN user dict

    '''
    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    import ckan.model
    users = ckan.model.User.by_email(email)

    assert len(users) in (0, 1), ("The SimpleSSO plugin doesn't know what to do "
                                  "when CKAN has more than one user with the "
                                  "same email address.")

    if users:
        # But we need to actually return a user dict, so we need to convert it
        # here.
        user = users[0]
        user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
        return user_dict
    else:
        return None


def generate_password():
    '''Generate a random password.

    '''
    # FIXME: Replace this with a better way of generating passwords, or enable
    # users without passwords in CKAN.
    return str(uuid.uuid4())
