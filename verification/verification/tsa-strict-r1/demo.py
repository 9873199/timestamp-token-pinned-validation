import sys
import rfc3161ng as ts
import rfc3161ng.api as api
from tsa_review_fixtures import authority,make_token,DATA,POLICY
from test_tsa_strict_review import response,verify,OTHER
x=make_token(authority())
print("Document timestamp validation")
print("Pinned TSA signature and matching request:", verify(x))
try: verify(x,policy=OTHER)
except ValueError as exc: print("Direct check with different policy: rejected ("+str(exc)+")")
class Reply:
    content=response(x)
    def raise_for_status(self): pass
original=api.requests.post
seen=[]
def offline_post(url,**kwargs):
    request=ts.decode_timestamp_request(kwargs['data']);seen.append(str(request['reqPolicy']))
    return Reply()
api.requests.post=offline_post
try:
    print("Actual request policy:",OTHER)
    print("Signed response policy:",POLICY)
    for full_response in (False,True):
        client=ts.RemoteTimestamper('https://offline.invalid/',certificate=x['certificate'],strict=True)
        result=client(data=DATA,nonce=x['nonce'],tsa_policy_id=OTHER,return_tsr=full_response)
        assert seen[-1]==OTHER
        print("Remote strict check, full response="+str(full_response)+": ACCEPTED")
    print("Request policy binding is incomplete.")
finally: api.requests.post=original
sys.exit(1)
