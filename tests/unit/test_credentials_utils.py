from unittest import TestCase
from hammr.utils import credentials_utils
from hammr.utils.credentials_utils import CredentialException
from mock import Mock,patch,MagicMock

__author__ = 'UShareSoft'


class TestCredential(TestCase):

    @patch('json.load')
    @patch('hammr.utils.credentials_utils.check_credfile')
    @patch('__builtin__.open')
    def test_fill_credentials_from_credfile(self, open, check_credfile, load):
        #Given
        cred = credentials_utils.Credential()
        open.return_value = MagicMock(spec=file)
        check_credfile.return_value = 'credential.json'
        load.return_value = {'url' : 'my_url', 'user' : 'my_user', 'publicKey' : 'my_publicKey', 'secretKey' : 'my_secretKey', 'acceptAutoSigned' : 'True'}
        #When
        cred.fill_credentials_from_credfile()
        #Then
        self.assertEqual(cred.credfile, "credentials.json", "Error : the credfile should be 'my_credfile'")
        self.assertEqual(cred.url, "my_url", "Error : the url should be 'my_url'")
        self.assertEqual(cred.username, "my_user", "Error : the username should be 'my_user'")
        self.assertEqual(cred.publicKey, "my_publicKey", "Error : the publicKey should be 'my_publicKey'")
        self.assertEqual(cred.secretKey, "my_secretKey", "Error : the secretKey should be 'my_secretKey'")
        self.assertEqual(cred.sslAutosigned, "True", "Error : the sslAutosigned should be 'True'")

    def test_check_url_presence_and_set_it(self):
        #Given
        cred = credentials_utils.Credential()
        #when #Then
        self.assertRaisesRegexp(CredentialException,"url not found in commands nor in credentials file",cred.check_url_presence)

    @patch('getpass.getpass')
    def test_check_password_and_set_it(self, getpass):
        #Given
        cred = credentials_utils.Credential()
        getpass.return_value = 'my_password'
        #when
        cred.check_password_and_set_it()
        #Then
        self.assertEqual(cred.password, "my_password", "Error : password is None -> should ask the user for password")

    @patch('json.load')
    @patch('hammr.utils.credentials_utils.check_credfile')
    @patch('__builtin__.open')
    def test_fill_credentials_from_credfile_url_is_none(self, open, check_credfile, load):
        #Given
        cred = credentials_utils.Credential()
        open.return_value = MagicMock(spec=file)
        check_credfile.return_value = 'credential.json'
        load.return_value = {'user' : 'my_user', 'publicKey' : 'my_publicKey', 'secretKey' : 'my_secretKey', 'acceptAutoSigned' : 'True'}
        #When #Then
        self.assertRaisesRegexp(CredentialException,"url not found in commands nor in credentials file",cred.fill_credentials_from_credfile)

    @patch('json.load')
    @patch('hammr.utils.credentials_utils.check_credfile')
    @patch('__builtin__.open')
    def test_fill_credentials_from_credfile_apiKeys_are_none_no_passwords(self, open, check_credfile, load):
        #Given
        cred = credentials_utils.Credential()
        open.return_value = MagicMock(spec=file)
        check_credfile.return_value = 'credential.json'
        load.return_value = {'url' : 'my_url', 'user' : 'my_user', 'acceptAutoSigned' : 'True'}
        #When #Then
        self.assertRaisesRegexp(CredentialException,"no password or no public-secret api key found in credentials file",cred.fill_credentials_from_credfile)
