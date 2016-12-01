# Marathon API access based on Marathon-LB
# https://github.com/mesosphere/marathon-lb
import json
import logging
import os
import sys
import time

import jwt
import requests
from itertools import cycle
from requests.auth import AuthBase
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Service(object):
    def __init__(self, marathon):
        self.__marathon = marathon


class Marathon(object):

    def __init__(self, hosts, auth, ca_cert=None, base_path=''):
        self.__hosts = hosts
        self.__auth = auth
        self.__cycle_hosts = cycle(self.__hosts)
        self.__verify = False
        self.__base_path = base_path
        if ca_cert:
            self.__verify = ca_cert

    def api_req_raw(self, method, path, auth, body=None, **kwargs):
        for host in self.__hosts:
            path_str = os.path.join(host, self.__base_path, 'v2')

            for path_elem in path:
                path_str = path_str + "/" + path_elem

            response = requests.request(
                method,
                path_str,
                auth=auth,
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                timeout=(3.05, 46),
                **kwargs
            )

            logger.debug("%s %s", method, response.url)
            if response.status_code == 200:
                break

        response.raise_for_status()

        if 'message' in response.json():
            response.reason = "%s (%s)" % (
                response.reason,
                response.json()['message'])

        return response

    def api_req(self, method, path, **kwargs):
        return self.api_req_raw(method, path, self.__auth,
                                verify=self.__verify, **kwargs).json()

    def create(self, app_json):
        return self.api_req('POST', ['apps'], app_json)

    def get_app(self, appid):
        logger.info('fetching app %s', appid)
        return self.api_req('GET', ['apps', appid])["app"]

    # Lists all running apps.
    def list(self):
        logger.info('fetching apps')
        return self.api_req('GET', ['apps'],
                            params={'embed': 'apps.tasks'})["apps"]

    def tasks(self):
        logger.info('fetching tasks')
        return self.api_req('GET', ['tasks'])["tasks"]

    def add_subscriber(self, callbackUrl):
        return self.api_req(
                'POST',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

    def remove_subscriber(self, callbackUrl):
        return self.api_req(
                'DELETE',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

    def get_event_stream(self):
        url = self.host + "/v2/events"
        logger.info(
            "SSE Active, trying fetch events from {0}".format(url))

        headers = {
            'Cache-Control': 'no-cache',
            'Accept': 'text/event-stream'
        }

        resp = requests.get(url,
                            stream=True,
                            headers=headers,
                            timeout=(3.05, 46),
                            auth=self.__auth,
                            verify=self.__verify)

        class Event(object):
            def __init__(self, data):
                self.data = data

        for line in resp.iter_lines():
            if line.strip() != '':
                for real_event_data in re.split(r'\r\n',
                                                line.decode('utf-8')):
                    if real_event_data[:6] == "data: ":
                        event = Event(data=real_event_data[6:])
                        yield event

    @property
    def host(self):
        return next(self.__cycle_hosts)


def set_marathon_auth_args(parser):
    parser.add_argument("--marathon-auth-credential-file",
                        help="Path to file containing a user/pass for "
                        "the Marathon HTTP API in the format of 'user:pass'."
                        )
    parser.add_argument("--auth-credentials",
                        help="user/pass for the Marathon HTTP API in the "
                             "format of 'user:pass'.")
    parser.add_argument("--dcos-auth-credentials",
                        default=os.getenv('DCOS_SERVICE_ACCOUNT_CREDENTIAL'),
                        help="DC/OS service account credentials")
    parser.add_argument("--marathon-ca-cert",
                        help="CA certificate for Marathon HTTPS connections")

    return parser


class DCOSAuth(AuthBase):
    def __init__(self, credentials, ca_cert):
        creds = json.loads(credentials)
        self.uid = creds['uid']
        self.private_key = creds['private_key']
        self.login_endpoint = creds['login_endpoint']
        self.verify = False
        self.auth_header = None
        self.expiry = 0
        if ca_cert:
            self.verify = ca_cert

    def __call__(self, auth_request):
        if not self.auth_header or int(time.time()) >= self.expiry - 10:
            self.expiry = int(time.time()) + 3600
            payload = {
                'uid': self.uid,
                # This is the expiry of the auth request params
                'exp': int(time.time()) + 60,
            }
            token = jwt.encode(payload, self.private_key, 'RS256')

            data = {
                'uid': self.uid,
                'token': token.decode('ascii'),
                # This is the expiry for the token itself
                'exp': self.expiry,
            }
            r = requests.post(self.login_endpoint,
                              json=data,
                              timeout=(3.05, 46),
                              verify=self.verify)
            r.raise_for_status()

            self.auth_header = 'token=' + r.cookies['dcos-acs-auth-cookie']

        auth_request.headers['Authorization'] = self.auth_header
        return auth_request


def get_marathon_auth_params(args):
    marathon_auth = None
    if args.marathon_auth_credential_file:
        with open(args.marathon_auth_credential_file, 'r') as f:
            line = f.readline().rstrip('\r\n')

        if line:
            marathon_auth = tuple(line.split(':'))
    elif args.auth_credentials:
        marathon_auth = \
            tuple(args.auth_credentials.split(':'))
    elif args.dcos_auth_credentials:
        return DCOSAuth(args.dcos_auth_credentials, args.marathon_ca_cert)

    if marathon_auth and len(marathon_auth) != 2:
        print(
            "Please provide marathon credentials in user:pass format"
        )
        sys.exit(1)

    return marathon_auth
