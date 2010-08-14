# Test classes inherit from the Django TestCase
from common import Common
import re

# needed to login to the admin
from django.conf import settings
from django.contrib.auth.models import User
from django.db.models.query import QuerySet
from django.core import mail
from django.core.urlresolvers import reverse

from django.template import Template, Context

class DjangoCommon(Common):
    """
    This class contains a number of custom assertions which
    extend the default Django assertions. Use this as the super
    class for you tests rather than django.test.TestCase
    """

    # A few useful helpers methods

    
    def get(self, name, *args, **kwargs):
        get_data = kwargs.pop('get_data', {})
        return self.client.get(reverse(name, args=args, kwargs=kwargs), data=get_data)

    def post(self, name, *args, **kwargs):
        post_data = kwargs.pop('post_data', {})
        return self.client.post(reverse(name, args=args, kwargs=kwargs), data=post_data)
    
    def login(self, username, password):
        self.assertTrue(self.client.login(username=username, password=password), "User failed login for %s:%s" % (username, password))

    def login_as_admin(self):
        "Create, then login as, an admin user"
        # Only create the user if they don't exist already ;)
        try:
            User.objects.get(username="admin")
        except User.DoesNotExist:
            user = User.objects.create_user('admin', 'admin@example.com', 'password')
            user.is_staff = True
            user.is_superuser = True
            user.save()

        if not self.client.login(username='admin', password='password'):
            raise Exception("Login failed")
    
    def get_from_context(self, res, key):
        try:
            return res.context[key]
        except KeyError:
            raise AssertionError("%s is not in context" % str(key))


    # Some assertions need to know which template tag libraries to load
    # so we provide a list of templatetag libraries
    template_tag_libraries = []

    def render(self, template, **kwargs):
        "Return the rendering of a given template including loading of template tags"
        template = "".join(["{%% load %s %%}" % lib for lib in self.template_tag_libraries]) + template
        return Template(template).render(Context(kwargs)).strip()

    # Custom assertions
    def assert_equal(self, *args, **kwargs):
        """
        Convert QuerySets to list.
        """
        args = list(args)
        for index, arg in enumerate(args):
            if isinstance(arg, QuerySet):
                args[index] = list(arg)
        
        self.assertEqual(*args, **kwargs)
    
    def assert_key_in_context(self, key, response):
        self.assert_key_exists(key, response.context)
    
    def assert_redirects_to_login(self, response):
        self.assert_redirects(response, "%s?%s=%s" % (settings.LOGIN_URL, "next", response.request['PATH_INFO']))
    
    def assert_redirects(self, *args, **kwargs):
        return self.assertRedirects(*args, **kwargs)
    
    def assert_response_contains(self, fragment, response):
        "Assert that a response object contains a given string"
        self.assert_(fragment in response.content, "Response should contain `%s' but doesn't:\n%s" % (fragment, response.content))

    def assert_response_doesnt_contain(self, fragment, response):
        "Assert that a response object does not contain a given string"
        self.assert_(fragment not in response.content, "Response should not contain `%s' but does:\n%s" % (fragment, response.content))

    def assert_render_matches(self, template, match_regexp, vars={}):
        "Assert than the output from rendering a given template with a given context matches a given regex"
        r = re.compile(match_regexp)
        actual = Template(template).render(Context(vars))
        self.assert_(r.match(actual), "Expected: %s\nGot: %s" % (
            match_regexp, actual
        ))

    def assert_code(self, response, code):
        "Assert that a given response returns a given HTTP status code"
        self.assertEqual(code, response.status_code, "HTTP Response status code should be %d, and is %d" % (code, response.status_code))

    def assertNotContains(self, response, text, status_code=200):  # overrides Django's assertion, because all diagnostics should be stated positively!!!
        """
        Asserts that a response indicates that a page was retrieved
        successfully, (i.e., the HTTP status code was as expected), and that
        ``text`` doesn't occurs in the content of the response.
        """
        self.assertEqual(response.status_code, status_code,
            "Retrieving page: Response code was %d (expected %d)'" %
                (response.status_code, status_code))
        text = smart_str(text, response._charset)
        self.assertEqual(response.content.count(text),
             0, "Response should not contain '%s'" % text)

    def assert_render(self, expected, template, **kwargs):
        "Asserts than a given template and context render a given fragment"
        self.assert_equal(expected, self.render(template, **kwargs))

    def assert_render_matches(self, match_regexp, template, vars={}):
        r = re.compile(match_regexp)
        actual = Template(template).render(Context(vars))
        self.assert_(r.match(actual), "Expected: %s\nGot: %s" % (
            match_regexp, actual
        ))

    def assert_doesnt_render(self, expected, template, **kwargs):
        "Asserts than a given template and context don't render a given fragment"
        self.assert_not_equal(expected, self.render(template, **kwargs))

    def assert_render_contains(self, expected, template, **kwargs):
        "Asserts than a given template and context rendering contains a given fragment"
        self.assert_contains(expected, self.render(template, **kwargs))

    def assert_render_doesnt_contain(self, expected, template, **kwargs):
        "Asserts than a given template and context rendering does not contain a given fragment"
        self.assert_doesnt_contain(expected, self.render(template, **kwargs))

    def assert_mail(self, funk):
        '''
        checks that the called block shouts out to the world

        returns either a single mail object or a list of more than one
        '''

        previous_mails = len(mail.outbox)
        funk()
        mails = mail.outbox[ previous_mails : ]
        assert [] != mails, 'the called block produced no mails'
        if len(mails) == 1:  return mails[0]
        return mails
    
    def assert_last_mail_sent_to(self, *to, **kwargs):
        msg = mail.outbox[-1]
        self.assert_equal(msg.to, list(to), **kwargs)

    def assert_latest(self, query_set, lamb):
        pks = list(query_set.values_list('pk', flat=True).order_by('-pk'))
        high_water_mark = (pks+[0])[0]
        lamb()

          # NOTE we ass-ume the database generates primary keys in monotonic order.
          #         Don't use these techniques in production,
          #          or in the presence of a pro DBA

        nu_records = list(query_set.filter(pk__gt=high_water_mark).order_by('pk'))
        if len(nu_records) == 1:  return nu_records[0]
        if nu_records:  return nu_records  #  treating the returned value as a scalar or list
                                           #  implicitly asserts it is a scalar or list
        source = open(lamb.func_code.co_filename, 'r').readlines()[lamb.func_code.co_firstlineno - 1]
        source = source.replace('lambda:', '').strip()
        model_name = str(query_set.model)

        self.assertFalse(True, 'The called block, `' + source +
                               '` should produce new ' + model_name + ' records')

    def deny_mail(self, funk):
        '''checks that the called block keeps its opinions to itself'''

        from django.core import mail
        previous_mails = len(mail.outbox)
        funk()
        mails = mail.outbox[ previous_mails : ]
        assert [] == mails, 'the called block should produce no mails'

    def assert_model_changes(self, mod, item, frum, too, lamb):
        source = open(lamb.func_code.co_filename, 'r').readlines()[lamb.func_code.co_firstlineno - 1]
        source = source.replace('lambda:', '').strip()
        model  = str(mod.__class__).replace("'>", '').split('.')[-1]

        should = '%s.%s should equal `%s` before your activation line, `%s`' % \
                  (model, item, frum, source)

        self.assertEqual(frum, mod.__dict__[item], should)
        lamb()
        mod = mod.__class__.objects.get(pk=mod.pk)

        should = '%s.%s should equal `%s` after your activation line, `%s`' % \
                  (model, item, too, source)

        self.assertEqual(too, mod.__dict__[item], should)
        return mod
