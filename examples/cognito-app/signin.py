"""A tiny Cognito sign-up / sign-in demo for open-infra (via the AWS-SDK shim).

Shows the end-user auth flow an application uses: sign up a user, confirm them, sign in with
USER_PASSWORD_AUTH, and receive real RS256 JWTs (id/access/refresh) that verify against the pool's JWKS —
the same tokens an API Gateway JWT authorizer (or any app) validates. Uses boto3 unmodified; only the
endpoint is pointed at the shim. The public calls (sign_up, initiate_auth) are UNSIGNED, exactly as on AWS.

    # control-plane setup (signed, an admin principal): create the pool + client
    AWS_ENDPOINT_URL=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566 \
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... python signin.py setup

    # end-user flow (unsigned): sign up + sign in
    AWS_ENDPOINT_URL=... python signin.py signin <pool-id> <client-id> alice 'Sup3r!Secret9'
"""
import sys
import boto3
from botocore import UNSIGNED
from botocore.config import Config


def endpoint():
    import os
    return os.environ.get("AWS_ENDPOINT_URL")


def admin_client():
    return boto3.client("cognito-idp", endpoint_url=endpoint())  # signed with your admin creds


def public_client():
    # end-user calls are unsigned (the user has no AWS credentials)
    return boto3.client("cognito-idp", endpoint_url=endpoint(), config=Config(signature_version=UNSIGNED))


def setup():
    c = admin_client()
    pool = c.create_user_pool(
        PoolName="demo",
        Policies={"PasswordPolicy": {"MinimumLength": 8, "RequireUppercase": True,
                                     "RequireLowercase": True, "RequireNumbers": True, "RequireSymbols": True}},
    )["UserPool"]["Id"]
    client = c.create_user_pool_client(UserPoolId=pool, ClientName="app",
                                       ExplicitAuthFlows=["USER_PASSWORD_AUTH"])["UserPoolClient"]["ClientId"]
    print(f"pool={pool}\nclient={client}")


def signin(pool, client, username, password):
    pub, adm = public_client(), admin_client()
    pub.sign_up(ClientId=client, Username=username, Password=password,
                UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    adm.admin_confirm_sign_up(UserPoolId=pool, Username=username)  # no email delivery; admin-confirm
    res = pub.initiate_auth(ClientId=client, AuthFlow="USER_PASSWORD_AUTH",
                            AuthParameters={"USERNAME": username, "PASSWORD": password})["AuthenticationResult"]
    print("signed in — tokens (verify against "
          f"{endpoint()}/cognito/{pool}/.well-known/jwks.json):")
    for k in ("IdToken", "AccessToken", "RefreshToken"):
        print(f"  {k}: {res[k][:32]}…")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "setup":
        setup()
    elif len(sys.argv) >= 6 and sys.argv[1] == "signin":
        signin(*sys.argv[2:6])
    else:
        print(__doc__)
        sys.exit(2)
