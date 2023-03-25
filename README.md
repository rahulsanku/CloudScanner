README for 'Cloud Scanner'

The tool is used to look for external cloud misconfigurations and does that for 3 platforms: AWS, Azure and GCP.
azure_perm derived from AzureBlobEnum.ps1 and gcp_perm derived from gcpbucketscanner.py


INSTRUCTIONS

run 'pip install -r requirements.txt' to run dependencies

run 'sudo apt-get install awscli' to install the AWS Client
then run aws configure to add credentials so that you can run the AWS AUTHENTICATED scan

Run the tool by using 'python3 CA-cloud-scan.py -h' and follow the help menu to choose the flags and what you want the tool to do

DESCRIPTION(to be changed)

The tool runs by making use of permutation lists (gcp_perm and azure_perm) These permutation lists can be modified by the user for a more comprehensive/quicker search if need be


TO BE FIXED

Printing to an outfile sometimes doesn't work
Authenticated Headers for GCP and Azure
Adding functionality for custom permuation lists
TBD
