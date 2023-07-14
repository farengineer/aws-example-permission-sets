# Example AWS SSO Permission Sets by Job Function
Below are example AWS SSO Permission Sets for job personas ( such as administrator, break-glass, development, readonly, billing analyst/admin, auditor/viewer, and pipeline admin roles). I will not be using AWS Managed Policies either to ensure 100% control over permissions for each persona. [Access Analyzer](https://aws.amazon.com/iam/features/analyze-access/) can be used after roles and policies are deployed to ensure roles are least privileged in your organization.

For these examples, I have some assumptions:

* SCPs and permissions boundaries exist to support these role policies.
* SLDC/AWS environment structure of Lab/Experiment→Dev→Stage→Prod with descending permissions for console roles as the environment goes up in level.
* IAC (example code below uses Terraform resources) is used in all environments and strictly required for 100% of all resources in Stage and Prod.

## Developer IAM Role

A role intended for developers to be able to test and create resources in lower environments. These permissions should be even more refined by keeping services you know are being used and removing services not used by developers for least privilege. Higher level environments should only be interacted with via a pipeline role and IAC unless there is an emergency in which a break-glass role should be used (state drift, I&R, etc).

### Lab
In a lab or experimental environment, you may be more lenient in permissions as this environment may not have internet access, no on-premises connectivity, or test/work with new services that aren’t approved/allowed in higher environments. SCPs and permission boundaries should still be enforced to restrict actions against critical infrastructure (in place networking, IAM roles managed by security, etc).

``` HCL
resource "aws_ssoadmin_permission_set" "developer_lab" {
  name             = "Developer-Lab"
  description      = "An example of a developer permission set in lab environment."
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  session_duration = "PT2H"
}

data "aws_iam_policy_document" "developer_lab_policy_document" {
  // Assuming SCP exist to stop potentially dangerous actions.
  statement {
    sid = ""
    effect = "Allow"
    actions = ["aws:*"] 
    resources = ["*"]
  }
}

resource "aws_iam_policy" "developer_lab_policy" {
  name   = "Developer-Lab-Policy"
  path   = "/security/"
  policy = data.aws_iam_policy_document.developer_lab_policy_document.json
}

resource "aws_ssoadmin_managed_policy_attachment" "developer_lab" {
  instance_arn       = aws_ssoadmin_permission_set.developer_lab.instance_arn
  managed_policy_arn = aws_iam_policy.developer_lab_policy.arn
  permission_set_arn = aws_ssoadmin_permission_set.developer_lab.arn
}
```

### Dev
In a dev environment, we should start to become more strict on permissions as this environment is where internet and on-premises connectivity may start to be a factor. Further, this is where developers aren’t experimenting but starting to develop an actual application that may end up in production; therefore, we want to allow only services/actions that the application can use in higher environments to avoid errors once the application is promoted to staging or production.

```HCL
resource "aws_ssoadmin_permission_set" "developer_dev" {
  name             = "Developer-Dev"
  description      = "An example of a developer permission set in dev environment."
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  session_duration = "PT2H"
}

data "aws_iam_policy_document" "developer_dev_policy_document" {
  statement {
    sid = "AllowDeveloperDevAccess"
    effect = "Allow"
    actions = [
      "acm:*",
      "apigateway:*",
      "application-autoscaling:*",
      "applicationinsights:*",
      "appmesh:*",
      "athena:*",
      "autoscaling:*",
      "autoscaling-plan:*",
      "backupstorage:*",
      "backup:*",
      "backup-storage:*",
      "batch:*",
      "chatbot:*",
      "cloudformation:*",
      "cloudfront:*",
      "cloudtrail:*",
      "cloudwatch:*", 
      "cloud9:*",
      "codeartifact:*",
      "codebuild:*",
      "codecommit:*",
      "codedeploy:*",
      "codedeploy-commands-secure:*",
      "codepipeline:*",
      "codestar:*",
      "codestar-connections:*",
      "codestar-notifications:*",
      "cognito-identity:*",
      "cognito-idp:*",
      "config:*",
      "comprehend:*",
      "comprehendmedical:*",
      "datasync:*",
      "datapipeline:*",
      "drs:*",
      "dynamodb:*",
      "ec2:*",
      "ec2-instance-connect:*",
      "ec2messages:*",
      "ebs:*",
      "ecr:*",
      "ecr-public:*",
      "ecs:*",
      "eks:*",
      "elasticache:*",
      "elasticbeanstalk:*",
      "elasticfilesystem:*",
      "elasticloadbalancing:*",
      "elasticmapreduce:*",
      "emr-containers:*",
      "emr-serverless:*",
      "es:*",
      "events:*",
      "execute-api:*",
      "firehose:*",
      "fsx:*",
      "glacier:*",
      "globalaccelerator:*",
      "glue:*",
      "iam:*"
      "kinesis:*",
      "kinesisanalytics:*",
      "kinesisvideo:*",
      "kms:*",
      "lakeformation:*",
      "lambda:*",
      "logs:*",
      "network-firewall:*",
      "networkmanager:*"
      "rds:*",
      "rds-data:*",
      "rds-db:*",
      "redshift:*",
      "redshift-data:*",
      "redshift-serverless:*",
      "resource-groups:*",
      "route53:*",
      "route53domains:*",
      "route53-recovery-cluster:*",
      "route53-recovery-control-config:*",
      "route53-recovery-readiness:*",
      "route53resolver:*",
      "s3:*",
      "s3-object-lambda:*",
      "schemas:*",
      "secretsmanager:*",
      "serverlessrepo:*",
      "servicecatalog:*",
      "ses:*",
      "ssm:*",
      "ssm-guiconnect:*",
      "ssmmessages:*",
      "sns:*",
      "sqs:*",
      "ssmmessages:*",
      "states:*",
      "swf:*",
      "waf:*",
      "waf-regional:*",
      "wafv2:*",
      "xray:*"
    ] 
    resources = ["*"]
  }
  
  // Example of denying dangerous actions.
  statement {
    sid = "DenyDangerousIAMActions"
    effect = "Deny"
    actions = ["iam:*"] 
    resources = [
      "arn:aws:iam:*:role/security/*",
      "arn:aws:iam:*:policy/security/*"
    ]
  }
  
  statement {
    sid = "DenyDangerousIAMActions_2"
    effect = "Deny"
    actions = [
      "iam:*AccessKeys*",
      "iam:*User*",
      "iam:*Group*",
    ] 
    resources = ["*"]
  }
}

resource "aws_iam_policy" "developer_dev_policy" {
  name   = "Developer-Dev-Policy"
  path   = "/security/"
  policy = data.aws_iam_policy_document.developer_dev_policy_document.json
}

resource "aws_ssoadmin_managed_policy_attachment" "developer_dev" {
  instance_arn       = aws_ssoadmin_permission_set.developer_dev.instance_arn
  managed_policy_arn = aws_iam_policy.developer_dev_policy.arn
  permission_set_arn = aws_ssoadmin_permission_set.developer_dev.arn
}
```

### Stage/Prod
Developers should use a read-only role for these environment.

### Developer Read-Only
Developers may need access to view resources in environments that are strictly managed by pipelines and IAC (Stage and Production). This is critical as IAC state drift may happen or something may be deployed with the wrong configuration and need to be viewed in the console by developers to validate.

At this level, it's crucial to differentiate the Control Plane and the Data Plane. For example, we want developers to be able to view details on a Secrets Manager Secret (Control Plane) in production but not the actual Secret (Data Plane). This is important because if this role is compromised, you do not want to expose confidential data but instead just the configuration of the data.


Note, some service:get* can be dangerous (i.e, secretsmanager:GetSecretValue) while others may be more benign and needed to view specific details about a resource (i.e, secretsmanager:GetResourcePolicy or iam:GetPolicyVersion). Therefore, each service:get<detailed_get_action> should be evaluated if we want this role to be able to perform a specific get for each service. 

```HCL
resource "aws_ssoadmin_permission_set" "developer_readonly" {
  name             = "Developer-ReadOnly"
  description      = "An example of a developer readonly permission set in stage/prod environment."
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  session_duration = "PT2H"
}

data "aws_iam_policy_document" "developer_readonly_policy_document" {
  statement {
    sid = "AllowDeveloperReadOnlyAccess"
    effect = "Allow"
    actions = [
      "acm:Describe*",
      "acm:List*",
      "apigateway:Get*",
      "application-autoscaling:Describe*",
      "applicationinsights:Describe*",
      "applicationinsights:List*",
      "appmesh:Describe*",
      "appmesh:List*",
      "athena:List*",
      "autoscaling:Describe*",
      "autoscaling-plans:Describe*",
      "backup:Describe*",
      "backup:List*",
      "batch:Describe*",
      "batch:List*",
      "chatbot:Describe*",
      "cloudformation:Describe*",
      "cloudformation:List*",
      "cloudfront:Describe*",
      "cloudfront:List*",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "codeartifact:Describe*",
      "codeartifact:List*",
      "codebuild:Describe*",
      "codebuild:List*",
      "codecommit:Describe*",
      "codecommit:List*",
      "codedeploy:List*",
      "codepipeline:List*",
      "codestar:List*",
      "codestar-connections:List*",
      "codestar-notifications:Describe*",
      "codestar-notifications:List*",
      "cognito-identity:Describe*",
      "cognito-identity:List*",
      "cognito-idp:Describe*",
      "cognito-idp:List*",
      "config:Describe*",
      "config:List*",
      "comprehend:Describe*",
      "comprehend:List*",
      "comprehendmedical:Describe*",
      "comprehendmedical:List*",
      "datasync:Describe*",
      "datasync:List*",
      "datapipeline:Describe*",
      "datapipeline:List*",
      "drs:*",
      "dynamodb:Describe*",
      "dynamodb:List*",
      "ec2:Descibe*",
      "ec2:List*",
      "ebs:List*",
      "ecr:Describe*",
      "ecr:List*",
      "ecr-public:Describe*",
      "ecr-public:List*",
      "ecs:Describe*",
      "ecs:List*",
      "eks:Describe*",
      "eks:List*",
      "elasticache:Describe*",
      "elasticache:List*",
      "elasticbeanstalk:Describe*",
      "elasticbeanstalk:List*",
      "elasticfilesystem:Describe*",
      "elasticfilesystem:List*",
      "elasticloadbalancing:Describe*",
      "elasticmapreduce:Describe*",
      "elasticmapreduce:List*",
      "emr-containers:Describe*",
      "emr-containers:List*",
      "emr-serverless:List*",
      "es:Describe*",
      "es:List*",
      "events:Describe*",
      "events:List*",
      "firehose:Describe*",
      "firehose:List*",
      "fsx:Describe*",
      "fsx:List*",
      "glacier:Describe*",
      "glacier:List*",
      "globalaccelerator:Describe*",
      "globalaccelerator:List*",
      "glue:List*",
      "iam:Describe*",
      "iam:List*",
      "kinesis:Describe*",
      "kinesis:List*",
      "kinesisanalytics:Describe*",
      "kinesisanalytics:List*",
      "kinesisvideo:Describe*",
      "kinesisvideo:List*",
      "kms:Describe*",
      "kms:List*",
      "lakeformation:Describe*",
      "lakeformation:List*",
      "lambda:Describe*",
      "lambda:List*",
      "logs:Describe*",
      "logs:List*",
      "network-firewall:Describe*",
      "network-firewall:List*",
      "networkmanager:Describe*",
      "networkmanager:List*",
      "rds:Describe*",
      "rds:List*",
      "redshift:Describe*",
      "redshift:List*",
      "redshift-data:Describe*",
      "redshift-data:List*",
      "redshift-serverless:List*",
      "resource-groups:List*",
      "route53:List*",
      "route53domains:List*",
      "route53-recovery-cluster:List*",
      "route53-recovery-control-config:Describe*",
      "route53-recovery-control-config:List*",
      "route53-recovery-readiness:List*",
      "route53resolver:List*",
      "s3:Describe*",
      "s3:List*",
      "s3-object-lambda:List*",
      "schemas:Describe*",
      "schemas:List*",
      "secretsmanager:Describe*",
      "secretsmanager:List*",
      "serverlessrepo:List*",
      "servicecatalog:Describe*",
      "servicecatalog:List*",
      "ses:Describe*",
      "ses:List*",
      "ssm:Describe*",
      "ssm:List*",
      "sns:List*",
      "sqs:List*",
      "states:Describe*",
      "states:List*",
      "swf:Describe*",
      "swf:List*",
      "waf:List*",
      "waf-regional:List*",
      "wafv2:Describe*",
      "wafv2:List*",
      "xray:List*"
    ] 
    resources = ["*"]
  }

resource "aws_iam_policy" "developer_readonly_policy" {
  name   = "Developer-ReadOnly-Policy"
  path   = "/security/"
  policy = data.aws_iam_policy_document.developer_readonly_policy_document.json
}

resource "aws_ssoadmin_managed_policy_attachment" "developer_readonly" {
  instance_arn       = aws_ssoadmin_permission_set.developer_readonly.instance_arn
  managed_policy_arn = aws_iam_policy.developer_readonly_policy.arn
  permission_set_arn = aws_ssoadmin_permission_set.developer_readonly.arn
}
```

## Pipeline IAM Role
The permissions for your pipeline may look very similar to a developer role in lower environments but across all environments. Further, the pipeline role may need to be adjust to not be blocked to perform certain dangerous actions such as editing roles and policies in the /security/ path, for instance. In this case, you should limit the number of pipelines with this permission as roles and policies in your /security/ path are critical and privileged.

This role should be monitored and unique per account - further, this role may differ based on the OU it is under as security related accounts will need the ability to interact with Guard Duty, Security Hub, etc while other accounts that are intended for applications teams wouldn’t (usually) need to interact with those services.
Your pipeline should only be able to perform actions on services that are approved for your organization unit. Further, it should be able to create other IAM Roles for other services like AWS Lambda. These IAM Roles should be in their own unique path to identify it as a pipeline role.

### Lab/Dev/Stage/Prod

```HCL
resource "aws_ssoadmin_permission_set" "pipeline_admin_dev" {
  name             = "PipelineAdmin-Dev"
  description      = "An example of a pipeline permission set in dev environment."
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  session_duration = "PT2H"
}

data "aws_iam_policy_document" "dpipeline_admin_dev_policy_document" {
  statement {
    sid = "AllowPipelineAdminDevAccess"
    effect = "Allow"
    actions = [
      "acm:*",
      "apigateway:*",
      "application-autoscaling:*",
      "applicationinsights:*",
      "appmesh:*",
      "athena:*",
      "autoscaling:*",
      "autoscaling-plan:*",
      "backupstorage:*",
      "backup:*",
      "backup-storage:*",
      "batch:*",
      "chatbot:*",
      "cloudformation:*",
      "cloudfront:*",
      "cloudtrail:*",
      "cloudwatch:*", 
      "cloud9:*",
      "codeartifact:*",
      "codebuild:*",
      "codecommit:*",
      "codedeploy:*",
      "codedeploy-commands-secure:*",
      "codepipeline:*",
      "codestar:*",
      "codestar-connections:*",
      "codestar-notifications:*",
      "cognito-identity:*",
      "cognito-idp:*",
      "config:*",
      "comprehend:*",
      "comprehendmedical:*",
      "datasync:*",
      "datapipeline:*",
      "drs:*",
      "dynamodb:*",
      "ec2:*",
      "ec2-instance-connect:*",
      "ec2messages:*",
      "ebs:*",
      "ecr:*",
      "ecr-public:*",
      "ecs:*",
      "eks:*",
      "elasticache:*",
      "elasticbeanstalk:*",
      "elasticfilesystem:*",
      "elasticloadbalancing:*",
      "elasticmapreduce:*",
      "emr-containers:*",
      "emr-serverless:*",
      "es:*",
      "events:*",
      "execute-api:*",
      "firehose:*",
      "fsx:*",
      "glacier:*",
      "globalaccelerator:*",
      "glue:*",
      "iam:*"
      "kinesis:*",
      "kinesisanalytics:*",
      "kinesisvideo:*",
      "kms:*",
      "lakeformation:*",
      "lambda:*",
      "logs:*",
      "network-firewall:*",
      "networkmanager:*"
      "rds:*",
      "rds-data:*",
      "rds-db:*",
      "redshift:*",
      "redshift-data:*",
      "redshift-serverless:*",
      "resource-groups:*",
      "route53:*",
      "route53domains:*",
      "route53-recovery-cluster:*",
      "route53-recovery-control-config:*",
      "route53-recovery-readiness:*",
      "route53resolver:*",
      "s3:*",
      "s3-object-lambda:*",
      "schemas:*",
      "secretsmanager:*",
      "serverlessrepo:*",
      "servicecatalog:*",
      "ses:*",
      "ssm:*",
      "ssm-guiconnect:*",
      "ssmmessages:*",
      "sns:*",
      "sqs:*",
      "ssmmessages:*",
      "states:*",
      "swf:*",
      "waf:*",
      "waf-regional:*",
      "wafv2:*",
      "xray:*"
    ] 
    resources = ["*"]
  }

resource "aws_iam_policy" "pipeline_admin_dev_policy" {
  name   = "PipelineAdmin-Dev-Policy"
  path   = "/security/"
  policy = data.aws_iam_policy_document.pipeline_admin_dev_policy_document.json
}

resource "aws_ssoadmin_managed_policy_attachment" "pipeline_admin_dev" {
  instance_arn       = aws_ssoadmin_permission_set.pipeline_admin_dev.instance_arn
  managed_policy_arn = aws_iam_policy.pipeline_admin_dev_policy.arn
  permission_set_arn = aws_ssoadmin_permission_set.pipeline_admin_dev.arn
}
```

## Security/Break-glass IAM Role
For your “everyday” security break-glass type roles, `aws:*` should actually be avoided, especially in higher environments. This is especially true if you already have an OrganizationAccountCrossAccountRole Role which is probably already aws:* (similar to Root User). 
The reason for this is to decrease the blast radius if this role is compromised in someway. If this role were to be compromised and was aws:* with no kind of guardrails in place an attacker could then create, update, or delete any resource in any environment. This is why still having guardrails and monitoring/alerting on access for this role is still very important. Your security break-glass role should be heavily monitored and access should have a defined process. It should also not have access to any services that can’t normally be interacted with or deployed to through the pipeline.
You may even considering removing all aws:create* actions as anything in higher environments should be deployed via a pipeline. Any actions performed by this break-glass role would more than likely be to correct configuration drift (an update action, or a delete if it’s broken enough), move an EC2 instance that is compromised to a quarantine VPC (an update), investigation, etc. If a resource is broken enough that it must be recreated, the delete action should be used to delete it and then recreated correctly via CICD.

One important constraint is you don’t want your security break-glass role to have elevated management permissions and permission to view secrets or data (control plane vs data plane) in most cases. Even an administrator role needs guardrails and separation of duties. If an application developer believes their secret is not populating correctly, they can use a developer read-only role to validate that - not an elevated role that could also change the secret or its configuration.

### Lab/Dev/Stage/Prod

```HCL
resource "aws_ssoadmin_permission_set" "security_all" {
  name             = "Security-All"
  description      = "An example of a security break-glass permission set in any environment."
  instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
  session_duration = "PT2H"
}

data "aws_iam_policy_document" "security_all_policy_document" {
  statement {
    sid = "AllowSecurityAccess"
    effect = "Allow"
    actions = [
      "acm:*",
      "apigateway:*",
      "application-autoscaling:*",
      "applicationinsights:*",
      "appmesh:*",
      "athena:*",
      "autoscaling:*",
      "autoscaling-plan:*",
      "backupstorage:*",
      "backup:*",
      "backup-storage:*",
      "batch:*",
      "chatbot:*",
      "cloudformation:*",
      "cloudfront:*",
      "cloudtrail:*",
      "cloudwatch:*", 
      "cloud9:*",
      "codeartifact:*",
      "codebuild:*",
      "codecommit:*",
      "codedeploy:*",
      "codedeploy-commands-secure:*",
      "codepipeline:*",
      "codestar:*",
      "codestar-connections:*",
      "codestar-notifications:*",
      "cognito-identity:*",
      "cognito-idp:*",
      "config:*",
      "comprehend:*",
      "comprehendmedical:*",
      "datasync:*",
      "datapipeline:*",
      "drs:*",
      "dynamodb:*",
      "ec2:*",
      "ec2-instance-connect:*",
      "ec2messages:*",
      "ebs:*",
      "ecr:*",
      "ecr-public:*",
      "ecs:*",
      "eks:*",
      "elasticache:*",
      "elasticbeanstalk:*",
      "elasticfilesystem:*",
      "elasticloadbalancing:*",
      "elasticmapreduce:*",
      "emr-containers:*",
      "emr-serverless:*",
      "es:*",
      "events:*",
      "execute-api:*",
      "firehose:*",
      "fsx:*",
      "glacier:*",
      "globalaccelerator:*",
      "glue:*",
      "iam:*"
      "kinesis:*",
      "kinesisanalytics:*",
      "kinesisvideo:*",
      "kms:*",
      "lakeformation:*",
      "lambda:*",
      "logs:*",
      "network-firewall:*",
      "networkmanager:*"
      "rds:*",
      "rds-data:*",
      "rds-db:*",
      "redshift:*",
      "redshift-data:*",
      "redshift-serverless:*",
      "resource-groups:*",
      "route53:*",
      "route53domains:*",
      "route53-recovery-cluster:*",
      "route53-recovery-control-config:*",
      "route53-recovery-readiness:*",
      "route53resolver:*",
      "s3:*",
      "s3-object-lambda:*",
      "schemas:*",
      "secretsmanager:*",
      "serverlessrepo:*",
      "servicecatalog:*",
      "ses:*",
      "ssm:*",
      "ssm-guiconnect:*",
      "ssmmessages:*",
      "sns:*",
      "sqs:*",
      "ssmmessages:*",
      "states:*",
      "swf:*",
      "waf:*",
      "waf-regional:*",
      "wafv2:*",
      "xray:*"
    ] 
    resources = ["*"]
  }
  
  // Example of permissions you would want to deny
  statement {
    sid = "DenyDangerousActions"
    effect = "Allow"
    actions = [
      "iam:Create*",
      "secretsmanager:GetSecretValue"
    ] 
    resources = ["*"]
  }
  
  // Potentially allow even further permission to assume a role that is aws:*
  statement {
    sid = "AssumeRole"
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ] 
    resources = ["arn:aws:iam:*:role/security/OrganizationCrossAccountRole]
  }
}

resource "aws_iam_policy" "security_all_policy" {
  name   = "Security-All-Policy"
  path   = "/security/"
  policy = data.aws_iam_policy_document.security_all_policy_document.json
}

resource "aws_ssoadmin_managed_policy_attachment" "security_all" {
  instance_arn       = aws_ssoadmin_permission_set.security_all.instance_arn
  managed_policy_arn = aws_iam_policy.security_all_policy.arn
  permission_set_arn = aws_ssoadmin_permission_set.security_all.arn
}
```
