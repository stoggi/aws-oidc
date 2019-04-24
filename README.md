# aws-oidc

Assume roles in AWS using an OpenID Connect Identity provider.

It outputs temporary AWS credentials in a JSON format that can be consumed by the credentials_process setting in ~/.aws/config.

https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes

Example:

    aws-oidc auth \
      --role_arn="arn:aws:iam::892845094662:role/onelogin-test-oidc" \
      --duration=3600 \
      --provider_url=https://openid-connect.onelogin.com/oidc \
      --client_id=97a61160-3c09-0137-8c69-0a1c3f4fd822144813 \
      --agent=open

All the provider arguments can be specified in a TOML configuration file:

    region = "ap-southeast-2"

    [[AuthProvider]]
    name = "onelogin"
    role_arn = "arn:aws:iam::012345678901:role/role-name"
    duration = 900
    provider_url = "https://openid-connect.onelogin.com/oidc"
    client_id = "ef061080-43aa-0137-62f3-066d8813aeb888900"
    agent = ["open", "-b", "com.google.chrome", "-n", "--args", "--profile-directory=Default", "{}"]

    [[AuthProvider]]
    name = "google"
    role_arn = "arn:aws:iam::012345678901:role/role-name"
    duration = 900
    provider_url = "https://accounts.google.com"
    client_id = "430784603061-osbtei3s71l0bj6d8oegto0itefjmiq6.apps.googleusercontent.com"
    agent = ["open", "-b", "com.google.chrome", "-n", "--args", "--profile-directory=Profile 1", "{}"]

This configuration file should be located in **~/.aws-oidc/config**

## Configure AWS Config

Add the profiles for each role you want to assume to **~/.aws/config**. Specify the provider name from the configuration file, and override any default settings:

    [profile engineer]
    credential_process = aws-oidc auth onelogin --role_arn=arn:aws:iam::892845094662:role/onelogin-test-oidc --duration 7200

Now you can use the AWS cli as normal, and specify the profile:

    $ aws --profile engineer sts get-caller-identity
    {
        "UserId": "AROAJUTXNWXGCAEILMXTY:50904038",
        "Account": "892845094662",
        "Arn": "arn:aws:sts::892845094662:assumed-role/onelogin-test-oidc/50904038"
    }

## Run other commands with credentials

Most AWS SDK's should be able to pick up the profile parameter, and suppor the `credentials_process` setting in your **~/.aws/config** file. If not, you can run an arbitary command with the temporary credentials with `exec`:

    aws-oidc exec engineer -- ./path/to/command with arguments

This will use the profiles defined in **~/.aws/config** to assume the role with `aws-oidc` and then set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables for the new process.

## Find roles that an oidc client could assume

Use the `list` command to find roles that your claim and client_id can assume:

    aws-oidc list --claim="openid-connect.onelogin.com/oidc:aud" --client_id="ef061080-43aa-0137-62f3-066d8813aeb888900"

Example using only the AWS CLI:

    aws iam list-roles --query <<EOF '
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
