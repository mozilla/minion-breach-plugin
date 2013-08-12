# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import urlparse

import minion.curly
from minion.plugins.base import AbstractPlugin, BlockingPlugin

class BreachPlugin(BlockingPlugin):
    """
    This plugin checks to see if a site is BREACH-vulnerable by
    looking at whether the site has HTTP compression enabled.
    """

    PLUGIN_NAME = "Breach"
    PLUGIN_WEIGHT = "light"
    FURTHER_INFO = [ 
        {
            "URL": "http://breachattack.com/",
            "Title": "BREACH ATTACK - Official Site"
        },
        {
            "URL": "http://www.kb.cert.org/vuls/id/987798",
            "Title": "Vulnerability Note VU#987798 - BREACH vulnerability in compressed HTTPS"
        },
        {
            "URL": "https://community.qualys.com/blogs/securitylabs/2013/08/07/defending-against-the-breach-attack",
            "Title": "Qualys - Defending against the BREACH Attack"
        },
        {
            "URL": "http://blogs.cisco.com/security/breach-crime-and-blackhat/",
            "Title": "Cisco - BREACH, CRIME, and Black Hat"
        },
        {
            "URL": "http://security.stackexchange.com/a/20407/9897",
            "Title": "IT Security Stack Exchange - Is HTTP compression safe?"
        }
    ]

    HTTP_SUBMITTED = "The target URL submitted is HTTP. BREACH is an attack \
against any protocol over TLS/SSL. Instead, Minion automatically tried the HTTPS \
version."

    REPORTS = {
        "disabled": 
            {
                "Summary": "HTTPS site is not vulnerable to BREACH attack",
                "Description": 'A HTTP request was sent out to the server with \
"Accept-Encoding: compress, gzip, deflate, bzip2, lzma" in the request header. \
The server responded with no HTTP compression.',
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None}],
                "FurtherInfo": FURTHER_INFO
            },
        "enabled": 
            {
                "Summary": "HTTPS site is vulnerable to BREACH attack",
                "Description": 'A HTTP request was sent out to the server with \
"Accept-Encoding: compress, gzip, deflate, bzip2, lzma" in the request header. \
The server replied with {header} in the response header.',
                "Severity": "High",
                "URLs": [ {"URL": None, "Extra": None}],
                "FurtherInfo": FURTHER_INFO
            },
        "netural":
            {
                "Summary": "HTTP site is not vulnerable to BREACH attack",
                "Description": "The BREACH attack is not applicable on HTTP site.",
                "Severity": "Info",
                "URLs": [{"URL": None, "Extra": None}],
                "FurtherInfo": FURTHER_INFO
            }
}

    def do_run(self):
        try:
            url_list = None
            was_http = False
            target = self.configuration['target']
            url = urlparse.urlparse(target)
            if url.scheme == 'http':
                target = target.replace('http', 'https')
                was_http = True
                url_list = [{'URL': target, 'Extra': self.HTTP_SUBMITTED}]

            r = minion.curly.get(
                target, 
                connect_timeout=5, 
                timeout=15,
                headers={'accept-encoding': 'compress, gzip, deflate, bzip2, lzma'})
            r.raise_for_status()

            # If HTTP compression is enabled
            if "content-encoding" in r.headers:
                header = 'Content-Encoding: ' + r.headers['content-encoding']
                issue = self._format_report('enabled', 
                    description_formats={'header': header},
                    url_list=url_list)
                self.report_issue(issue)
            else:
                issue = self._format_report('disabled', url_list=url_list)
                self.report_issue(issue)
        except minion.curly.CurlyError as error:
            if not was_http:
                url_list = [{'URL': target, 'Extra': 'Site not reachable'}]
            else:
                url_list[0]['Extra'] = 'HTTPS destination is not reachable. ' + \
                    url_list[0]['Extra']
            issue = self._format_report('netural', 
                description=str(error),
                url_list=url_list)
            self.report_issue(issue)
        except minion.curly.BadResponseError as error:
            self.report_issue(error.issue)
            return AbstractPlugin.EXIT_STATE_ABORTED

    def _append_url(issue, urls):
        c = 0
        for url in urls:
            issue['URLs'][c] = url
            c += 1
        return issue

