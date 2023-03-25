import os
import re
import sys
import warnings
import requests
import boto3
import botocore
import socket
import xmltodict
import argparse
import textwrap
import json

from datetime import datetime, timedelta
from os.path import expanduser
from collections import defaultdict
from urllib.request import urlopen
from functools import partial

globals()['boto3'] = boto3
globals()['botocore'] = botocore




#Processing Functions
def outprint(data='', file_path='', normal_print=''):
    with open(file_path, 'a+') as f:
        f.write('{}\n'.format(data))

    normal_print(data)

def open_wordlist(file):
    array = []
    try:
        read = open(file, 'r')
        for line in read:
            line = line.strip()
            array.append(line)
        read.close()
        return array
    except FileNotFoundError:
        print('Error: File not found')
        exit(1)
    except PermissionError:
        print('Error: Permission denied')
        exit(1)



def check_bucket_open(bucket_name):
    s3client = boto3.client('s3')
    try:
        objects = s3client.list_objects(Bucket=bucket_name)
        print("Found the following open AWS bucket(s): ")
        print("    "+bucket_name)
        print("")
        print("Listing bucket contents...")
        print("")

        for x in objects['Contents']:
             print(x['Key'])

    except botocore.exceptions.ClientError:
        print("AWS Bucket is not open to the public \n")

def check_metadata(url_to_check):
    urls_to_scan = [
        "https://{}/latest/meta-data".format(url_to_check),
        "http://{}/latest/meta-data".format(url_to_check),
        "https://{}/proxy/169.254.169.254/latest/meta-data".format(url_to_check),
        "http://{}/proxy/169.254.169.254/latest/meta-data".format(url_to_check),
    ]
    warnings.filterwarnings("ignore")
    for url in urls_to_scan:
        try:
            content = requests.get(url)
            print("metadata found")
        except Exception:
            print("metadata not found")
            continue

def scan_bucket_urls(bucket_name):


    domain = "s3.amazonaws.com"
    access_urls = []
    urls_to_scan = [
        "https://{}.{}".format(bucket_name, domain),
        "http://{}.{}".format(bucket_name, domain),
        "https://{}/{}".format(domain, bucket_name),
        "http://{}/{}".format(domain, bucket_name)
    ]
    warnings.filterwarnings("ignore")
    for url in urls_to_scan:
        try:
            content = requests.get(url).text
        except requests.exceptions.SSLError:
            continue
        if not re.search("Access Denied", content):
            access_urls.append(url)
    return access_urls


#Azure codebase


def dns_lookup(lookup):
    try:
        data=socket.gethostbyname_ex(lookup)
        ip = repr(data)
        return ip
    except Exception:
        return False


def parse_xml(url):
    data = urlopen(url).read()

    data = xmltodict.parse(data)
    print("  Found public file on " + data['EnumerationResults']['Blobs']['Blob']['Url'])
    # print(data['EnumerationResults']['Blobs']['Blob']['Url'])



def azure_blob_enum(company_name):

    domain=".blob.core.windows.net"
    lookup=(company_name+domain).lower()
    url_list=[]
    if dns_lookup(lookup):
        url_list.append(lookup)
    file = open("azure_perm.txt", 'r')
    for line in file:
        line=line.strip()
        lookup = (line + company_name + domain).lower()
        if dns_lookup(lookup):
            url_list.append(lookup)

        lookup = (company_name + line + domain).lower()
        if dns_lookup(lookup):
            url_list.append(lookup)

    file.close()
    print("Found the following storage account(s):")
    for i in url_list:
        print("      "+i)
    print("")
    print("Enumerating through storage account(s) for containers...")
    for subDomain in url_list:

        file = open("azure_perm.txt", 'r')
        for line in file:


            line = line.strip()
            dirGuess = (subDomain+"/"+line).lower()

            uriGuess = "https://"+dirGuess+"?restype=container"
            print("Trying " + uriGuess)
            try:
                r=requests.get(uriGuess)
                status = str(r.status_code)

            except Exception:
                continue
            if status == "200":
                print("")
                print("Found container on "+dirGuess)

                uriList = "https://"+dirGuess+"?restype=container" + "&comp=list"



                parse_xml(uriList) #fails if no data in container - fix
                print("")



        file.close()

def azure_resource_enum(word):
    subDomain =  {'.onmicrosoft.com':'Microsoft Hosted Domain',
					'.scm.azurewebsites.net':'App Services - Management',
					'.azurewebsites.net':'App Services',
					'.p.azurewebsites.net':'App Services',
					'.cloudapp.net':'App Services',
					'.file.core.windows.net':'Storage Accounts - Files',
					'.queue.core.windows.net':'Storage Accounts - Queues',
					'.table.core.windows.net':'Storage Accounts - Tables',
					'.mail.protection.outlook.com':'Email',
					'.sharepoint.com':'SharePoint',
					'.redis.cache.windows.net':'Databases-Redis',
					'.documents.azure.com':'Databases-Cosmos DB',
					'.database.windows.net':'Databases-MSSQL',
					'.vault.azure.net':'Key Vaults',
					'.azureedge.net':'CDN',
					'.search.windows.net':'Search Appliance',
					'.azure-api.net':'API Services',}
    url_list=[]
    for key in subDomain:
        if dns_lookup(word+key):
            url_list.append(word+key)
            print("Found the following service account: "+word+key +" - "+subDomain[key])



#GCP codebase
#codebase obained from gcpbucket.py

def generate_bucket_permutations(keyword, permutation):
    permutation_templates = [
        '{keyword}-{permutation}',
        '{permutation}-{keyword}',
        '{keyword}_{permutation}',
        '{permutation}_{keyword}',
        '{keyword}{permutation}',
        '{permutation}{keyword}'
    ]
    with open(permutation, 'r') as f:
        permutations = f.readlines()
        buckets = []

        for perm in permutations:
            perm = perm.rstrip()
            for template in permutation_templates:
                generated_string = template.replace('{keyword}', keyword).replace('{permutation}', perm)
                buckets.append(generated_string)


    buckets.append('{}.com'.format(keyword))
    buckets.append('{}.net'.format(keyword))
    buckets.append('{}.org'.format(keyword))
    buckets = list(set(buckets))
    buckets[0]=keyword

    for bucket in buckets:
        if len(bucket) < 3 or len(bucket) > 63:
            del buckets[bucket]

    return buckets

def check_google_buckets(keyword, permutation='./gcp_perm.txt'):
    buckets = generate_bucket_permutations(keyword, permutation)
    print('    Found the following bucket(s):')
    for bucket_name in buckets:
        unauthenticated_permissions = requests.get('https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'.format(bucket_name)).json()

        if unauthenticated_permissions.get('permissions'):
            print('\n    Found an open bucket {}'.format(bucket_name))
            if 'storage.buckets.setIamPolicy' in unauthenticated_permissions['permissions']:
                print('        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)')
            if 'storage.objects.list' in unauthenticated_permissions['permissions']:
                print('        - UNAUTHENTICATED LISTABLE (storage.objects.list)')
            if 'storage.objects.get' in unauthenticated_permissions['permissions']:
                print('        - UNAUTHENTICATED READABLE (storage.objects.get)')
            if 'storage.objects.create' in unauthenticated_permissions['permissions'] or 'storage.objects.delete' in unauthenticated_permissions['permissions'] or 'storage.objects.update' in unauthenticated_permissions['permissions']:
                print('        - UNAUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)')
            print('        - Permissions allowed:')
            print(textwrap.indent('{}\n'.format(json.dumps(unauthenticated_permissions['permissions'], indent=4)), '            '))

        if not (unauthenticated_permissions.get('permissions')):
            print('    Bucket: {}'.format(bucket_name))

def main(args):
    if args.out_file:
        global print
        normal_print = print
        print = partial(outprint, file_path=args.out_file, normal_print=normal_print)
    if args.wordlist:
        wordlist = open_wordlist(args.wordlist)
        for word in wordlist:
            azure_blob_enum(word)
            azure_resource_enum(word)
            check_bucket_open(word)
            check_google_buckets(word)
    if args.url:
        url_to_scan = args.url
        check_bucket_open(url_to_scan)
        azure_blob_enum(url_to_scan)
        azure_resource_enum(url_to_scan)
        check_google_buckets(url_to_scan)
    if args.out_file:
        print = normal_print
    if args.aws:
        check_bucket_open(args.aws)
    if args.azure:
        azure_blob_enum(args.azure)
        azure_resource_enum(args.azure)
    if args.gcp:
        check_google_buckets(args.gcp)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description ='Scan for cloud misconfigurations using keywords')
    parser.add_argument('-o', '--out-file', required=False, default=None, help='The path to a log file to write the scan results to. The file will be created if it does not exist and will append to it if it already exists. By default output will only print to the screen.')
    parser.add_argument('-w', '--wordlist', required=False, default=None, help='The path to a wordlist file')
    parser.add_argument('-u', '--url', required=False, default=None, help='The URL of a site to scan')
    parser.add_argument('-a', '--aws', required=False, default=None, help='Check for AWS bucket')
    parser.add_argument('-g', '--gcp', required=False, default=None, help='Check for GCP bucket')
    parser.add_argument('-z', '--azure', required=False, default=None, help='Check for Azure Bucket')
    parser.add_argument('-k', '--custom-permutation', required=False, default=None, help='The path to a custom permutation list to check for possible buckets')
    args = parser.parse_args()
    main(args)
