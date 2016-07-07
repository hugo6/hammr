from unittest import TestCase
from hammr.utils import credentials_utils
from mock import Mock,patch,MagicMock

__author__ = 'UShareSoft'


class TestCredential(TestCase):
    def test_fill_credentials_from_cmd_apiKey(self):
        #Given
        mock = Mock()
        attrs = {'user': 'my_user','url': 'my_url', 'publicKey': 'my_publicKey', 'secretKey':'my_secretKey' }
        mock.configure_mock(**attrs)
        cred = credentials_utils.Credential()
        #When
        cred.fill_credentials_from_cmd_apiKey(mock)
        #Then
        self.assertEqual(cred.username, "my_user", "Error : the username should be 'my_user'")
        self.assertEqual(cred.url, "my_url", "Error : the url should be 'my_url'")
        self.assertEqual(cred.publicKey, "my_publicKey", "Error : the publicKey should be 'my_publicKey'")
        self.assertEqual(cred.secretKey, "my_secretKey", "Error : the secretKey should be 'my_secretKey'")
        self.assertEqual(cred.apikeysAuthentication, True, "Error : apikeysAuthentication should be True")

    def test_check_url_presence_and_set_it(self):
        #Given
        url = None
        cred = credentials_utils.Credential()
        #when
        with self.assertRaises(SystemExit) as cm:
            cred.check_url_presence_and_set_it(url)
        #Then
        self.assertEqual(cm.exception.code, 1, "Error : url is None -> should exit")

    def test_fill_credentials_from_cmd_user_password(self):
        #Given
        mock = Mock()
        attrs = {'url': 'my_url', 'user': 'my_user','password': 'my_password', 'userpassAuthentication':'my_userpassAuthentication' }
        mock.configure_mock(**attrs)
        cred = credentials_utils.Credential()
        #When
        cred.fill_credentials_from_cmd_user_password(mock)
        #Then
        self.assertEqual(cred.url, "my_url", "Error : the url should be 'my_url'")
        self.assertEqual(cred.username, "my_user", "Error : the username should be 'my_user'")
        self.assertEqual(cred.password, "my_password", "Error : the password should be 'my_password'")
        self.assertEqual(cred.userpassAuthentication, True, "Error : the userpassAuthentication should be True")

    @patch('getpass.getpass')
    def test_check_password_and_set_it(self, getpass):
        #Given
        pw = None
        cred = credentials_utils.Credential()
        getpass.return_value = 'my_password'
        #when
        cred.check_password_and_set_it(pw)
        #Then
        self.assertEqual(cred.password, "my_password", "Error : password is None -> should ask the user for password")

    @patch('json.load')
    @patch('hammr.utils.credentials_utils.check_credfile')
    @patch('__builtin__.open')
    def test_fill_credentials_from_credfile(self, open, check_credfile, load):
        #Given
        mock = Mock()
        attrs = {'credentials': 'my_credfile', 'url' : None}
        mock.configure_mock(**attrs)
        cred = credentials_utils.Credential()
        open.return_value = MagicMock(spec=file)
        check_credfile.return_value = 'credential.json'
        load.return_value = {'url' : 'my_url', 'user' : 'my_user', 'publicKey' : 'my_publicKey', 'secretKey' : 'my_secretKey', 'acceptAutoSigned' : 'True'}
        #When
        cred.fill_credentials_from_credfile(mock)
        #Then
        self.assertEqual(cred.credfile, "my_credfile", "Error : the credfile should be 'my_credfile'")
        self.assertEqual(cred.url, "my_url", "Error : the url should be 'my_url'")
        self.assertEqual(cred.username, "my_user", "Error : the username should be 'my_user'")
        self.assertEqual(cred.publicKey, "my_publicKey", "Error : the publicKey should be 'my_publicKey'")
        self.assertEqual(cred.secretKey, "my_secretKey", "Error : the secretKey should be 'my_secretKey'")
        self.assertEqual(cred.sslAutosigned, "True", "Error : the sslAutosigned should be 'True'")

    @patch('json.load')
    @patch('hammr.utils.credentials_utils.check_credfile')
    @patch('__builtin__.open')
    def test_fill_credentials_from_credfile_url_is_none(self, open, check_credfile, load):
        #Given
        mock = Mock()
        attrs = {'credentials': 'my_credfile', 'url' : None}
        mock.configure_mock(**attrs)
        cred = credentials_utils.Credential()
        open.return_value = MagicMock(spec=file)
        check_credfile.return_value = 'credential.json'
        load.return_value = {'user' : 'my_user', 'publicKey' : 'my_publicKey', 'secretKey' : 'my_secretKey', 'acceptAutoSigned' : 'True'}
        #When
        with self.assertRaises(SystemExit) as cm:
            cred.fill_credentials_from_credfile(mock)
        #Then
        self.assertEqual(cm.exception.code, 1, "Error : url is None -> should exit")

    @patch('json.load')
    @patch('hammr.utils.credentials_utils.check_credfile')
    @patch('__builtin__.open')
    def test_fill_credentials_from_credfile_apiKeys_are_none_no_passwords(self, open, check_credfile, load):
        #Given
        mock = Mock()
        attrs = {'credentials': 'my_credfile', 'url' : None, 'password' : None}
        mock.configure_mock(**attrs)
        cred = credentials_utils.Credential()
        open.return_value = MagicMock(spec=file)
        check_credfile.return_value = 'credential.json'
        load.return_value = {'url' : 'my_url', 'user' : 'my_user', 'acceptAutoSigned' : 'True'}
        #When
        with self.assertRaises(SystemExit) as cm:
            cred.fill_credentials_from_credfile(mock)
        #Then
        self.assertEqual(cm.exception.code, 1, "Error : no apiKeys in the credential file or no password in command line or no password in credential file -> should exit")