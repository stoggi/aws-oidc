# aws-oidc

Assume roles in AWS using an OpenID Connect Identity provider.

It outputs temporary AWS credentials in a JSON format that can be consumed by the credentials_process setting in ~/.aws/config.

https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes

OneLogin Example:

	aws-oidc exec \
	  --role_arn="arn:aws:iam::892845094662:role/onelogin-test-oidc" \
	  --provider_url=https://openid-connect.onelogin.com/oidc \
	  --client_id=97a61160-3c09-0137-8c69-0a1c3f4fd822144813 \
	  --pkce \
	  --nonce \
	  -- open -b com.google.chrome -n --args --profile-directory=Default {}

Google Example:

    aws-oidc exec \
      --role_arn="arn:aws:iam::892845094662:role/web-identity-lanbda" \
      --provider_url=https://accounts.google.com \
      --client_id=430784603061-osbtei3s71l0bj6d8oegto0itefjmiq6.apps.googleusercontent.com \
      --client_secret=... \
      --pkce \
      --nonce \
      -- open -b com.google.chrome -n --args --profile-directory=Default {}

For some reason, even when using PKCE, google need a client_secret for applications not registered as Android, iOS or Chrome.

## Configure AWS Config

~/.aws/config

    [profile oidc]
    credential_process = aws-oidc exec --role_arn=arn:aws:iam::892845094662:role/onelogin-test-oidc --provider_url=https://openid-connect.onelogin.com/oidc --client_id=97a61160-3c09-0137-8c69-0a1c3f4fd822144813 --pkce --nonce -- open -b com.google.chrome -n --args --profile-directory=Default {}

Now you can use the AWS cli as normal, and specify the profile:

    $ aws --profile oidc sts get-caller-identity
    {
        "UserId": "AROAJUTXNWXGCAEILMXTY:50904038",
        "Account": "892845094662",
        "Arn": "arn:aws:sts::892845094662:assumed-role/onelogin-test-oidc/50904038"
    }

## AWS Cognito

    ./aws-oidc exec \
    --provider_url=https://cognito-idp.us-west-2.amazonaws.com/us-west-2_eBYNmnpS9 \
    --client_id=70kdnvprlqf1daspkn0iikdngv \
    --pkce \
    --nonce \
    --no-reauth \
    -- open -b com.google.chrome -n --args --profile-directory=Default {}

## Find roles that an oidc client could assume

    aws-vault exec test-privileged-admin -- aws iam list-roles --query <<EOF '
    Roles[?
      AssumeRolePolicyDocument.Statement[?
        Condition.StringEquals."openid-connect.onelogin.com/oidc:aud"
      ]
    ].{
      RoleName:RoleName,
      Arn:Arn,
      ClientId:AssumeRolePolicyDocument.Statement[*].Condition.StringEquals."openid-connect.onelogin.com/oidc:aud" | [0]
    } | [?
      contains(ClientId, `ef061080-43aa-0137-62f3-066d8813aeb888900`)
    ]'
    EOF