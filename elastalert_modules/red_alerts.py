from elastalert.alerts import Alerter, BasicMatchString
import os
from slack import WebClient

class SlackPasswordAlerter(Alerter):

    def __init__(self, rule):
        super(SlackPasswordAlerter, self).__init__(rule)
        self.sk = os.environ.get('SLACK_KEY')    # get slack api key
        self.scn = os.environ.get('SLACK_CHANNEL_NAME', 'password-alerts')     # get channel name

    def send_slack_msg(self, sendstr):
        tok = self.sk
        sc = WebClient(token=tok)  
        channels = sc.channels_list(exclude_archived=1).get('channels')
        scid = ""
        for ch in channels:
            if ch.get('name') == self.scn:
                scid = ch.get('id')
                break
            else:
                scid = ""
        sc.chat_postMessage(
            channel=scid,
            text=sendstr
        )
        return

    # Alert is called
    def alert(self, matches):

        for match in matches:
                match_string = ":rotating_light: :rotating_light: New credential for {}: {}: {}".format(match['host'], match['username'], match['password'])
                self.send_slack_msg(match_string)

    def get_info(self):
        return {'type': 'Slack Password Alerter',
                'Slack Channel': self.scn}

    