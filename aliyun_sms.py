from datetime import datetime
from hashlib import sha1
import base64
import urllib
import string
import random
import hmac
import urllib.request
import http.client


class AliyunSms(object):

    # SET YOUR ACCESS KEY ID and ACCESS KEY SECRET
    AccessKeyID = "<your own>"
    AccessKeySecret = "<your own>"

    # SET Your SMS signature, must be audited
    SignName = "<your own>"

    # SET Your Template Code, must be audited
    TemplateCode = "<your own>"

    def __init__(self):
        super(AliyunSms, self).__init__()
        self.payload = {'Action': 'SingleSendSms',
                        'SignName': AliyunSms.SignName,
                        'TemplateCode': AliyunSms.TemplateCode,
                        'RecNum': '',           # TODO
                        'ParamString': '',      # TODO
                        'Format': 'json',
                        'Version': '2016-09-27',
                        'Signature': '',        # TODO
                        'SignatureMethod': 'HMAC-SHA1',
                        'SignatureNonce': '',   # TODO
                        'SignatureVersion': '1.0',
                        'AccessKeyId': AliyunSms.AccessKeyID,
                        'Timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'RegionId': 'cn-hangzhou'
                        }

    def id_generator(self, size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
        return ''.join(random.choice(chars) for _ in range(size))

    def _get_req_string(self, key, value):
        return key + "=" + value

    def _percent_encode(self, string):
        return urllib.parse.quote(string, safe='-_.~')

    def send_sms(self, recnum, smsparam):

        paramstr = ""
        reqstr = ""

        self.payload['RecNum'] = recnum
        self.payload['ParamString'] = smsparam
        self.payload['SignatureNonce'] = self.id_generator(16)

        print(self.payload)

        for key in sorted(self.payload.keys()):
            if key != 'Signature':
                paramstr = paramstr + self._get_req_string(self._percent_encode(key), self._percent_encode(self.payload[key]))
                paramstr += "&"
                reqstr = reqstr + self._get_req_string(key, self.payload[key])
                reqstr += "&"

        string_to_sign = "POST" + "&" + self._percent_encode('/') + "&" + self._percent_encode(paramstr[:-1])

        # Calculate Signature, HMAC-SHA1
        secret_key = AliyunSms.AccessKeySecret + "&"
        hmac_obj = hmac.new(secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), sha1)
        signature = self._percent_encode(base64.b64encode(hmac_obj.digest()).decode('utf-8'))

        self.payload['Signature'] = signature

        reqbody = "Signature=" + signature + "&" + reqstr[:-1]
        print("Request Body:", reqbody)

        headerdata = {
            "Content-Type": "application/x-www-form-urlencoded",
            "charset": "utf-8"
        }
        conn = http.client.HTTPSConnection('sms.aliyuncs.com')
        conn.request(method='POST', url='https://sms.aliyuncs.com/', body=reqbody.encode('utf-8'), headers=headerdata)

        response = conn.getresponse()
        res = response.read()

        print("Response:", res)

        return res

if __name__ == '__main__':

    sms = AliyunSms()
    sms.send_sms("", "")
