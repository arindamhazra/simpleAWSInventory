# simpleAWSInventory
This a simple AWS Cloudformation stack to do Inventory of AWS Account using Lambda Function.
This Cloudformatio stack creates following resources in to the account we run it:
1. An S3 Bucket to store Inventory results.Final Bucket/Prefix structure will be like
    <Unique Bucket Name>/<AccountId>/<Year>/<Month>/<Inventoryfile>.csv
2. A IAM Role and Policy to allow Lambda Function to query AWS Resources with minimum permission.
3. A Lambda Function (.zip) file comtaining Python script and other Libraries from an S3 Bucket.
4. Cloudwatch Log Event to Schedule the executaion of the Lambda Function created in Step 3.
  
Pre-requisites:
1. An unique S3 Bucket Name.Clone/Download attached Cloudformation Stack(.yaml) and the Lambda Function .Zip File in to it.
2. An unique S3 Bucket Name to store the output of Lambda Function 

Parameters:
1. Name of S3 Bucket to store output
2. Name of S3 Bucket hosting the .Zip file
3. Name of S3 Key (.Zip file)
4. cron schedule time(default 12 AM UTC everyday)
5. Lambda Function Timeout(default is Max 300 Sec)
6. Allocated Memory to Lambda Function(default 512 MB)
