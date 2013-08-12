# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import minion.curly

from minion.plugins.base import BlockingPlugin

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

    REPORTS = {
        "good": 
            {
                "Summary": "HTTP compression is not enabled",
                "Description": 'A HTTP request was sent out to the server with \
"Accept-Encoding: compress, gzip, deflate, bzip2, lzma" in the request header. \
The server responded with no HTTP compression.',
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None}],
                "FurtherInfo": FURTHER_INFO
            },
        "bad": 
            {
                "Summary": "HTTP compression is enabled",
                "Description": 'A HTTP request was sent out to the server with \
"Accept-Encoding: compress, gzip, deflate, bzip2, lzma" in the request header. \
The server replied with {header} in the response header',
                "Severity": "High",
                "URLs": [ {"URL": None, "Extra": None}],
                "FurtherInfo": FURTHER_INFO
            }
}

    def do_run(self):
        try:
            r = minion.curly.get(
                self.configuration['target'], 
                connect_timeout=5, 
                timeout=15,
                headers={'accept-encoding': 'compress, gzip, deflate, bzip2, lzma'})
            r.raise_for_status()
            if "content-encoding" in r.headers:
                header = 'Content-Encoding: ' + r.headers['content-encoding']
                issue = self._format_report('bad', 
                    description_formats={'header': header})
                self.report_issue(issue)
            else:
                self.report_issue(self.REPORTS['good'])
        except minion.curly.CurlyError as error:
            self.report_issue(error.issue)
            return AbstractPlugin.EXIT_STATE_ABORTED
        except minion.curly.BadResponseError as error:
            issue = self._format_report('bad', description=str(error))
            self.report_issue(issue)
            return AbstractPlugin.EXIT_STATE_ABORTED
